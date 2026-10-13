-- Where the master reaches a node, beyond its address.
--
-- rpc_port: the port the node's inbound RPC listener is bound to. The
-- master used to dial 9443 unconditionally while install-node.sh let the
-- operator pick another port, so any node installed on a different one
-- was enrolled, heartbeating — and unreachable. NULL = 9443, which is
-- what every node enrolled before this column listened on.
--
-- external_ip: the node's public address when `public_ip` holds a private
-- one (`[remote_rpc] advertise_addr`, the recommended private-network
-- setup). `public_ip` is what the master DIALS; this is what customers
-- connect to — FTP hosts and DNS hints for sites on that node used to
-- show the private address. NULL = public_ip is the public address.
ALTER TABLE nodes ADD COLUMN rpc_port INTEGER;
ALTER TABLE nodes ADD COLUMN external_ip TEXT;
