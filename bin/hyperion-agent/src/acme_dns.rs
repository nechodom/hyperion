//! The acme-dns responder's sockets: serves the delegated `_acme-challenge`
//! zone on UDP + TCP 53 of every non-loopback interface address. Packet
//! logic is `hyperion_core::acme_dns_answer`; this file only binds, rate
//! limits and keeps the zone snapshot fresh.
//!
//! Runs only while the stored config says `enabled` — that row is written
//! by the master's explicit `AcmeDnsConfigSet`, never by cluster sync, so a
//! worker never starts answering DNS on its own.

use hyperion_core::acme_dns_status::{self, Status};
use hyperion_core::{acme_dns_answer, acme_dns_answer_tcp, AcmeDnsZoneView};
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

const PORT: u16 = 53;
const CONFIG_EVERY: Duration = Duration::from_secs(10);
const ZONE_REFRESH: Duration = Duration::from_secs(1);
const MAX_UDP: usize = 1232;
const TCP_MAX_CONNS: usize = 32;
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(5);
const RATE_QPS: f64 = 20.0;
const RATE_BURST: f64 = 40.0;
/// Hard cap on tracked sources. At the cap, idle (already full) buckets
/// are dropped; if that frees too little (a spoofed-source flood), the map
/// is cleared. Either way the next prune is at least a quarter of the cap
/// of new sources away, so memory is bounded and the cost O(1) amortised.
const RATE_MAX_SOURCES: usize = 10_000;

pub fn spawn(pool: SqlitePool) {
    tokio::spawn(run(pool));
}

/// What a running responder was started for; any change rebinds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Wanted {
    zone: String,
    ns_host: String,
    check_token: String,
    addrs: Vec<IpAddr>,
}

async fn run(pool: SqlitePool) {
    let mut running: Option<(Wanted, Vec<JoinHandle<()>>)> = None;
    let mut last_logged: Option<String> = None;
    loop {
        let cfg = match hyperion_state::acme_dns::config_get(&pool).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "acme-dns: could not read the config");
                tokio::time::sleep(CONFIG_EVERY).await;
                continue;
            }
        };
        let wanted = match cfg {
            Some(c) if c.enabled => match c.zone {
                Some(zone) => Some(Wanted {
                    zone,
                    ns_host: c.ns_host,
                    check_token: c.check_token,
                    addrs: interface_addrs().await,
                }),
                None => None,
            },
            _ => None,
        };
        // A bind that failed is retried every pass; a healthy one is only
        // touched when what it serves (or where) changed.
        let healthy = acme_dns_status::get().last_error.is_none();
        if running.as_ref().map(|(w, _)| w) != wanted.as_ref() || !healthy {
            if let Some((_, tasks)) = running.take() {
                // Await each so its socket is closed before the rebind.
                for t in tasks {
                    t.abort();
                    let _ = t.await;
                }
            }
            match wanted {
                Some(w) => {
                    let (tasks, status) = start(&pool, &w).await;
                    if status.last_error != last_logged {
                        match &status.last_error {
                            Some(e) => tracing::warn!(error = %e, "acme-dns: responder"),
                            None => tracing::info!(
                                zone = %w.zone,
                                listening = ?status.listening,
                                "acme-dns: responder listening"
                            ),
                        }
                        last_logged = status.last_error.clone();
                    }
                    acme_dns_status::set(status);
                    running = Some((w, tasks));
                }
                None => {
                    acme_dns_status::set(Status::default());
                    last_logged = None;
                }
            }
        }
        tokio::time::sleep(CONFIG_EVERY).await;
    }
}

async fn start(pool: &SqlitePool, w: &Wanted) -> (Vec<JoinHandle<()>>, Status) {
    let shared = Arc::new(Shared::new(
        pool.clone(),
        w.zone.clone(),
        w.ns_host.clone(),
        w.check_token.clone(),
    ));
    let mut tasks = Vec::new();
    let mut status = Status::default();
    let mut errors = Vec::new();
    if w.addrs.is_empty() {
        errors.push("no non-loopback interface address to bind".to_string());
    }
    for ip in &w.addrs {
        let addr = SocketAddr::new(*ip, PORT);
        let udp = UdpSocket::bind(addr).await;
        let tcp = TcpListener::bind(addr).await;
        match (udp, tcp) {
            (Ok(u), Ok(t)) => {
                tasks.push(tokio::spawn(serve_udp(u, shared.clone())));
                tasks.push(tokio::spawn(serve_tcp(t, shared.clone())));
                status.listening.push(addr.to_string());
            }
            (u, t) => {
                let e = u
                    .err()
                    .or(t.err())
                    .map(|e| e.to_string())
                    .unwrap_or_default();
                errors.push(format!("bind {addr}: {e}"));
            }
        }
    }
    if !errors.is_empty() {
        status.last_error = Some(errors.join("; "));
    }
    (tasks, status)
}

/// Per-source token bucket: `RATE_QPS` sustained, `RATE_BURST` at once,
/// excess dropped silently (no REFUSED to amplify).
struct RateLimiter {
    buckets: HashMap<IpAddr, (f64, Instant)>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }

    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if self.buckets.len() >= RATE_MAX_SOURCES && !self.buckets.contains_key(&ip) {
            self.buckets.retain(|_, (tokens, last)| {
                *tokens + now.saturating_duration_since(*last).as_secs_f64() * RATE_QPS < RATE_BURST
            });
            if self.buckets.len() > RATE_MAX_SOURCES * 3 / 4 {
                self.buckets.clear();
            }
        }
        let (tokens, last) = self.buckets.entry(ip).or_insert((RATE_BURST, now));
        let refill = now.saturating_duration_since(*last).as_secs_f64() * RATE_QPS;
        *tokens = (*tokens + refill).min(RATE_BURST);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct Cached {
    view: Arc<AcmeDnsZoneView>,
    /// `None` until the first read.
    at: Option<Instant>,
}

/// What every socket task shares: the limiter and the zone snapshot,
/// re-read from the DB at most every `ZONE_REFRESH`.
struct Shared {
    pool: SqlitePool,
    limiter: Mutex<RateLimiter>,
    cache: tokio::sync::Mutex<Cached>,
    tcp_slots: Arc<Semaphore>,
}

impl Shared {
    fn new(pool: SqlitePool, zone: String, ns_host: String, check_token: String) -> Self {
        let view = AcmeDnsZoneView {
            zone: zone.to_ascii_lowercase(),
            ns_host,
            check_token,
            serial: 0,
            txt: HashMap::new(),
            known_labels: HashSet::new(),
        };
        Self {
            pool,
            limiter: Mutex::new(RateLimiter::new()),
            cache: tokio::sync::Mutex::new(Cached {
                view: Arc::new(view),
                at: None,
            }),
            tcp_slots: Arc::new(Semaphore::new(TCP_MAX_CONNS)),
        }
    }

    fn allow(&self, ip: IpAddr) -> bool {
        self.limiter
            .lock()
            .map(|mut l| l.allow(ip, Instant::now()))
            .unwrap_or(false)
    }

    async fn view(&self) -> Arc<AcmeDnsZoneView> {
        let mut c = self.cache.lock().await;
        if c.at.is_some_and(|at| at.elapsed() < ZONE_REFRESH) {
            return c.view.clone();
        }
        c.at = Some(Instant::now());
        let now = hyperion_types::now_secs();
        let (txt, labels) = match (
            hyperion_state::acme_dns::values_live(&self.pool, now).await,
            hyperion_state::acme_dns::labels_all(&self.pool).await,
        ) {
            (Ok(t), Ok(l)) => (t, l),
            (Err(e), _) | (_, Err(e)) => {
                // Keep serving the last snapshot rather than nothing.
                tracing::warn!(error = %e, "acme-dns: could not refresh the zone");
                return c.view.clone();
            }
        };
        let known_labels: HashSet<String> = labels.into_iter().map(|l| l.label).collect();
        if txt != c.view.txt || known_labels != c.view.known_labels {
            c.view = Arc::new(AcmeDnsZoneView {
                zone: c.view.zone.clone(),
                ns_host: c.view.ns_host.clone(),
                check_token: c.view.check_token.clone(),
                // Bumped on every change so a secondary would notice;
                // seconds keep it moving forward across agent restarts.
                serial: (now as u32).max(c.view.serial.wrapping_add(1)),
                txt,
                known_labels,
            });
        }
        c.view.clone()
    }
}

async fn serve_udp(sock: UdpSocket, shared: Arc<Shared>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                // ICMP-induced errors surface here on Linux; never spin.
                tracing::debug!(error = %e, "acme-dns: udp recv");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        if !shared.allow(peer.ip()) {
            continue;
        }
        let view = shared.view().await;
        if let Some(reply) = acme_dns_answer(&buf[..n], &view, MAX_UDP) {
            let _ = sock.send_to(&reply, peer).await;
        }
    }
}

async fn serve_tcp(listener: TcpListener, shared: Arc<Shared>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "acme-dns: tcp accept");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        // Full: drop the connection rather than queue it.
        let Ok(permit) = shared.tcp_slots.clone().try_acquire_owned() else {
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_tcp_conn(stream, peer.ip(), &shared).await;
        });
    }
}

/// RFC 1035 §4.2.2: each message is prefixed by its 2-byte length.
async fn serve_tcp_conn(mut stream: TcpStream, ip: IpAddr, shared: &Shared) {
    let mut buf = vec![0u8; 65535];
    loop {
        let mut len = [0u8; 2];
        let read = async {
            stream.read_exact(&mut len).await?;
            let n = u16::from_be_bytes(len) as usize;
            stream.read_exact(&mut buf[..n]).await.map(|_| n)
        };
        let n = match tokio::time::timeout(TCP_READ_TIMEOUT, read).await {
            Ok(Ok(n)) => n,
            _ => return,
        };
        if !shared.allow(ip) {
            return;
        }
        let view = shared.view().await;
        let Some(reply) = acme_dns_answer_tcp(&buf[..n], &view) else {
            return;
        };
        let Ok(rlen) = u16::try_from(reply.len()) else {
            return;
        };
        if stream.write_all(&rlen.to_be_bytes()).await.is_err()
            || stream.write_all(&reply).await.is_err()
        {
            return;
        }
    }
}

/// Non-loopback interface addresses from `ip -j addr show`.
async fn interface_addrs() -> Vec<IpAddr> {
    match tokio::process::Command::new("ip")
        .args(["-j", "addr", "show"])
        .output()
        .await
    {
        Ok(o) if o.status.success() => addrs_from_ip_json(&String::from_utf8_lossy(&o.stdout)),
        _ => Vec::new(),
    }
}

/// Loopback is skipped (systemd-resolved lives there) and so is IPv6
/// link-local, which cannot be bound without a scope id.
fn addrs_from_ip_json(json: &str) -> Vec<IpAddr> {
    let Ok(serde_json::Value::Array(ifaces)) = serde_json::from_str(json) else {
        return Vec::new();
    };
    let mut out: Vec<IpAddr> = ifaces
        .iter()
        .filter_map(|i| i.get("addr_info")?.as_array())
        .flatten()
        .filter_map(|a| a.get("local")?.as_str()?.parse::<IpAddr>().ok())
        .filter(|ip| match ip {
            IpAddr::V4(v4) => !v4.is_loopback(),
            IpAddr::V6(v6) => !v6.is_loopback() && (v6.segments()[0] & 0xffc0) != 0xfe80,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_drops_after_burst() {
        let mut l = RateLimiter::new();
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        let other: IpAddr = "198.51.100.1".parse().expect("ip");
        let t0 = Instant::now();
        for i in 0..40 {
            assert!(l.allow(ip, t0), "query {i} is within the burst");
        }
        assert!(!l.allow(ip, t0), "the 41st at once is dropped");
        assert!(l.allow(other, t0), "buckets are per source");
        // One second refills 20.
        let t1 = t0 + Duration::from_secs(1);
        for i in 0..20 {
            assert!(l.allow(ip, t1), "refilled query {i}");
        }
        assert!(!l.allow(ip, t1));
    }

    #[test]
    fn interface_addrs_skip_loopback_and_link_local() {
        let json = r#"[
          {"ifindex":1,"ifname":"lo","addr_info":[
            {"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"},
            {"family":"inet6","local":"::1","prefixlen":128,"scope":"host"}]},
          {"ifindex":2,"ifname":"eth0","addr_info":[
            {"family":"inet","local":"203.0.113.5","prefixlen":24,"scope":"global"},
            {"family":"inet6","local":"2001:db8::5","prefixlen":64,"scope":"global"},
            {"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]},
          {"ifindex":3,"ifname":"eth1","addr_info":[
            {"family":"inet","local":"10.0.0.5","prefixlen":8,"scope":"global"}]}
        ]"#;
        let got: Vec<String> = addrs_from_ip_json(json)
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert_eq!(got, vec!["10.0.0.5", "203.0.113.5", "2001:db8::5"]);
        assert!(addrs_from_ip_json("not json").is_empty());
    }

    /// A TXT query for `name`, no EDNS.
    fn txt_query(id: u16, name: &str) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&[0, 16, 0, 1]);
        q
    }

    /// A responder whose zone serves one label with one value; returns the label.
    async fn seeded_shared(values: &[String]) -> (Arc<Shared>, String) {
        let pool = hyperion_state::open_memory().await.expect("db");
        let label = hyperion_state::acme_dns::label_ensure(&pool, "example.com", None, 1)
            .await
            .expect("label");
        hyperion_state::acme_dns::values_set(
            &pool,
            &label.label,
            values,
            hyperion_types::now_secs() + 600,
        )
        .await
        .expect("values");
        let shared = Arc::new(Shared::new(
            pool,
            "acme.panel.example".into(),
            "ns-acme.panel.example".into(),
            "t".repeat(32),
        ));
        (shared, label.label)
    }

    #[tokio::test]
    async fn udp_loop_answers_on_an_ephemeral_port() {
        let (shared, label) = seeded_shared(&["challenge-value-1".into()]).await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = sock.local_addr().expect("addr");
        tokio::spawn(serve_udp(sock, shared));
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
        client
            .send_to(
                &txt_query(0x4242, &format!("{label}.acme.panel.example")),
                addr,
            )
            .await
            .expect("send");
        let mut buf = [0u8; 1500];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("reply in time")
            .expect("recv");
        let reply = &buf[..n];
        assert_eq!(&reply[..2], &[0x42, 0x42]);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1, "one answer");
        assert!(
            reply
                .windows(b"challenge-value-1".len())
                .any(|w| w == b"challenge-value-1"),
            "the TXT value is served"
        );
    }

    #[tokio::test]
    async fn tcp_loop_answers_with_length_framing() {
        // Twenty 43-char values: well over 512 bytes, which is why the
        // client came over TCP — the reply must not be truncated again.
        let values: Vec<String> = (0..20).map(|i| format!("{i:0>43}")).collect();
        let (shared, label) = seeded_shared(&values).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(serve_tcp(listener, shared));
        let mut s = TcpStream::connect(addr).await.expect("connect");
        let q = txt_query(7, &format!("{label}.acme.panel.example"));
        s.write_all(&(q.len() as u16).to_be_bytes())
            .await
            .expect("len");
        s.write_all(&q).await.expect("query");
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.expect("reply len");
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut reply).await.expect("reply");
        assert!(reply.len() > 512, "{} bytes", reply.len());
        assert_eq!(reply[2] & 0x02, 0, "TC is clear");
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 20, "every value");
        for v in &values {
            assert!(reply.windows(v.len()).any(|w| w == v.as_bytes()), "{v}");
        }
    }

    #[test]
    fn rate_limiter_map_stays_capped_under_a_source_flood() {
        let mut l = RateLimiter::new();
        let t0 = Instant::now();
        for i in 0..(2 * RATE_MAX_SOURCES as u32) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            assert!(l.allow(ip, t0), "a new source gets its burst");
            assert!(l.buckets.len() <= RATE_MAX_SOURCES);
        }
    }
}
