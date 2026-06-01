//! Node.js stack: systemd unit template + nginx reverse-proxy variant.
//!
//! Foundation hosts PHP; this module renders the artifacts a future deploy
//! step needs to spin up a Node.js app. Real deploy (`npm ci`, `npm run
//! build`, `systemctl restart`) is wired through the agent once the Node.js
//! sub-project is exercised against a Linux integration test environment.

use crate::AdapterError;
use askama::Template;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct UnitInput<'a> {
    pub system_user: &'a str,
    pub domain: &'a str,
    pub node_version: &'a str,
    pub app_entry: &'a str,
    pub listen_port: u16,
    pub env_vars_secret_id: &'a str,
    pub memory_mb: u32,
    pub cpu_quota_pct: u32,
    pub tasks_max: u32,
}

#[derive(Template)]
#[template(path = "systemd-node-app.service.j2", escape = "none")]
struct UnitTpl<'a> {
    system_user: &'a str,
    domain: &'a str,
    node_version: &'a str,
    app_entry: &'a str,
    listen_port: u16,
    env_vars_secret_id: &'a str,
    memory_mb: u32,
    cpu_quota_pct: u32,
    tasks_max: u32,
}

/// Render the systemd unit content without writing anywhere.
pub fn render_unit(input: &UnitInput<'_>) -> Result<String, AdapterError> {
    let tpl = UnitTpl {
        system_user: input.system_user,
        domain: input.domain,
        node_version: input.node_version,
        app_entry: input.app_entry,
        listen_port: input.listen_port,
        env_vars_secret_id: input.env_vars_secret_id,
        memory_mb: input.memory_mb,
        cpu_quota_pct: input.cpu_quota_pct,
        tasks_max: input.tasks_max,
    };
    Ok(tpl.render()?)
}

pub fn unit_path(system_user: &str) -> PathBuf {
    PathBuf::from(format!(
        "/etc/systemd/system/hyperion-app-{system_user}.service"
    ))
}

/// Render a reverse-proxy nginx vhost that fronts a localhost Node app.
pub fn render_reverse_proxy_vhost(
    domain: &str,
    aliases: &[String],
    listen_port: u16,
    cert_path: &str,
    key_path: &str,
    acme_challenge_root: &str,
    logs_dir: &str,
) -> Result<String, AdapterError> {
    let alias_part: String = if aliases.is_empty() {
        String::new()
    } else {
        let names: Vec<&str> = aliases.iter().map(String::as_str).collect();
        format!(" {}", names.join(" "))
    };
    Ok(format!(
        r#"server {{
    listen 80;
    listen [::]:80;
    server_name {domain}{alias_part};
    location /.well-known/acme-challenge/ {{ root {acme_root}; }}
    location / {{ return 301 https://$host$request_uri; }}
}}

server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {domain}{alias_part};
    ssl_certificate     {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    server_tokens off;
    access_log {logs}/access.log;
    error_log  {logs}/error.log;

    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }}
}}
"#,
        domain = domain,
        alias_part = alias_part,
        acme_root = acme_challenge_root,
        cert = cert_path,
        key = key_path,
        logs = logs_dir,
        port = listen_port,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_unit_contains_key_directives() {
        let out = render_unit(&UnitInput {
            system_user: "alice_app",
            domain: "alice.app",
            node_version: "20",
            app_entry: "server.js",
            listen_port: 30042,
            env_vars_secret_id: "01J7A",
            memory_mb: 512,
            cpu_quota_pct: 200,
            tasks_max: 500,
        })
        .expect("render");
        assert!(out.contains("Description=hyperion app: alice.app (Node 20)"));
        assert!(out.contains("User=alice_app"));
        assert!(out.contains("ExecStart=/usr/bin/node20 server.js"));
        assert!(out.contains("PORT=30042"));
        assert!(out.contains("MemoryMax=512M"));
        assert!(out.contains("CPUQuota=200%"));
        assert!(out.contains("TasksMax=500"));
        assert!(out.contains("NoNewPrivileges=true"));
        assert!(out.contains("EnvironmentFile=-/etc/hyperion/secrets/01J7A"));
    }

    #[test]
    fn unit_path_is_predictable() {
        assert_eq!(
            unit_path("alice_app").to_string_lossy(),
            "/etc/systemd/system/hyperion-app-alice_app.service"
        );
    }

    #[test]
    fn render_reverse_proxy_vhost_works() {
        let aliases = vec!["www.alice.app".to_string()];
        let out = render_reverse_proxy_vhost(
            "alice.app",
            &aliases,
            30042,
            "/etc/lm/certs/alice.app/fullchain.pem",
            "/etc/lm/certs/alice.app/privkey.pem",
            "/var/lib/lm/acme",
            "/home/alice_app/alice.app/logs",
        )
        .expect("render");
        assert!(out.contains("server_name alice.app www.alice.app;"));
        assert!(out.contains("proxy_pass http://127.0.0.1:30042;"));
        assert!(out.contains("Upgrade $http_upgrade"));
        assert!(out.contains("acme-challenge"));
        assert!(out.contains("Strict-Transport-Security"));
    }
}
