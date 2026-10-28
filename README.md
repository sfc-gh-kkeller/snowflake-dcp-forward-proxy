# Snowflake DCP agent through a corporate HTTP forward proxy (lab reference)

This repository describes one option for running the Snowflake Data Connectivity Proxy (DCP) agent on a Linux VM where direct outbound TCP/443 is blocked and all internet egress goes through a corporate HTTP `CONNECT` proxy with SSL pass-through.

> **Support status.** Snowflake's DCP documentation states that routing the agent through an enterprise forward proxy (`HTTPS_PROXY` / CONNECT-based forwarding) is **not a supported deployment option**, and that DCP traffic requires end-to-end TLS without inspection, decryption, certificate substitution or termination. See [DCP security: corporate proxy support](https://docs.snowflake.com/en/user-guide/data-connectivity-proxy-security). This repository is engineering reference material for a lab evaluation. Snowflake has not certified this configuration.

## Summary of findings

| Question | Result |
|---|---|
| Does the DCP agent honour `HTTP_PROXY` / `HTTPS_PROXY`? | No. The variables are ignored and the agent dials TCP/443 directly. |
| Does the agent have a "custom proxy URL" option? | No. `DCP_CONNECTION_MODE` (`auto`, `direct-only`, `fallback-only`) only chooses between Snowflake relay hostnames. It does not configure an enterprise proxy. |
| Does TLS inspection break DCP? | Yes, by design. The agent uses mTLS with a pinned Snowflake CA. The proxy must pass TLS through untouched. |
| Can an HTTP CONNECT hop carry the DCP TLS session unchanged? | Yes. With the raw-TLS bridge in this repo, a real TLS 1.3 handshake to the DCP control-plane hostname completed through a local CONNECT proxy, and the Snowflake certificate was presented end to end. |
| Does `fallback-only` mode work? | Yes. With direct egress, the agent bootstrapped, obtained certificates and reported `AGENT_HEALTH = HEALTHY` using only the fallback relay hostname. |

The approach: the agent cannot be made proxy-aware, but the Linux VM can be. Netfilter intercepts the agent's outbound TCP/443 connections, and a local redirector turns each one into an HTTP `CONNECT` tunnel through the corporate proxy. The original DCP TLS/mTLS session is carried unchanged inside the tunnel, so there is no inherent TLS barrier.

```text
DCP agent (host network namespace)
   | plain TCP/443 to a Snowflake DCP hostname
   v
netfilter nat OUTPUT -> REDIRECT
   v
local redirector (redsocks / Python bridge / tun2socks / ...)
   | HTTP CONNECT <dcp-host>:443
   v
corporate forward proxy (SSL pass-through, no inspection)
   | opaque TLS bytes
   v
Snowflake DCP control plane / relay
```

## Prerequisites to check with the proxy team

- **No TLS inspection** for the DCP hostnames. Get the list from `SYSTEM$ALLOWLIST()`:

  ```sql
  SELECT f.VALUE:host::STRING AS host, f.VALUE:port::INT AS port, f.VALUE:type::STRING AS type
  FROM TABLE(FLATTEN(input => PARSE_JSON(SYSTEM$ALLOWLIST()))) f
  WHERE f.VALUE:type::STRING LIKE 'DCP%';
  ```

  Also allow the telemetry hostname delivered at bootstrap (`<org>-<account>.telemetry.<locator>.snowflakecomputing.com`).
- **CONNECT allowed to port 443** for those hostnames from the VM's source IP.
- **Long-lived tunnels.** DCP holds connections open. Check the proxy's idle and maximum tunnel lifetimes. Short limits cause reconnect churn.
- **Authentication.** Source-IP authorisation is simplest. redsocks supports Basic auth (`login`/`password`). NTLM and Kerberos usually need a local helper such as `cntlm` or `px` in front of the proxy.
- **CONNECT target form.** Some proxies allow-list by hostname. Redirectors that only know the destination IP send `CONNECT <ip>:443`, which hostname-based policies may reject. See [Hostname vs IP in CONNECT](#hostname-vs-ip-in-connect).

## Reference implementation: redsocks on Debian/Ubuntu

Assumptions:

- Dedicated Debian/Ubuntu VM, sudo access, Docker Engine.
- Proxy at `10.20.30.40:3128` (plain HTTP CONNECT listener). Replace with real values.
- Proxy access authorised by VM source IP.
- All internet-bound IPv4 TCP/443 from the VM is redirected. Private destinations stay direct, so DCP can still reach private data sources.
- DCP runs with `--network host`, so its traffic passes through the `OUTPUT` chain.

### 1. Install the redirector

```bash
sudo apt-get update
sudo apt-get install -y redsocks iptables
sudo systemctl disable --now redsocks          # avoid a competing packaged instance
id dcp-egress >/dev/null 2>&1 || \
  sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin dcp-egress
```

Save the following as `/etc/redsocks-dcp.conf`:

```text
base {
    log_debug = off;
    log_info = on;
    log = stderr;
    daemon = off;
    redirector = iptables;
}

redsocks {
    local_ip = 127.0.0.1;
    local_port = 12345;
    ip = 10.20.30.40;
    port = 3128;
    type = http-connect;
    // login = "user";      // only if Basic auth is required
    // password = "secret"; // keep the file mode 640
}
```

Run redsocks as a systemd service:

```bash
sudo chown root:dcp-egress /etc/redsocks-dcp.conf
sudo chmod 640 /etc/redsocks-dcp.conf
REDSOCKS_BIN=$(command -v redsocks); test -n "$REDSOCKS_BIN" || exit 1
sudo -u dcp-egress "$REDSOCKS_BIN" -t -c /etc/redsocks-dcp.conf

sudo tee /etc/systemd/system/dcp-egress.service >/dev/null <<UNIT
[Unit]
Description=Transparent TCP to corporate CONNECT proxy
Wants=network-online.target
After=network-online.target

[Service]
User=dcp-egress
Group=dcp-egress
ExecStart=$REDSOCKS_BIN -c /etc/redsocks-dcp.conf
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now dcp-egress.service
```

### 2. Redirect outbound TCP/443

Check the VM's existing firewall first. Do not flush existing rules.

```bash
PROXY_IP=10.20.30.40          # exclude every proxy IP if there are several

sudo iptables -t nat -N DCP_HTTPS
sudo iptables -t nat -A DCP_HTTPS -d "$PROXY_IP/32" -j RETURN         # no loop
for NET in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
  sudo iptables -t nat -A DCP_HTTPS -d "$NET" -j RETURN               # keep private paths direct
done
sudo iptables -t nat -A DCP_HTTPS -p tcp -j REDIRECT --to-ports 12345
sudo iptables -t nat -I OUTPUT 1 -p tcp --dport 443 -j DCP_HTTPS

# This reference handles IPv4 only. Block IPv6 TCP/443 so it cannot bypass the proxy.
sudo ip6tables -I OUTPUT 1 -p tcp --dport 443 -j REJECT --reject-with tcp-reset
```

As an alternative to excluding the proxy by IP, you could exclude the redirector's own traffic by user: `-m owner --uid-owner dcp-egress -j RETURN`. These are runtime rules. Persist them through the VM's firewall manager (`iptables-persistent`, nftables config, firewalld) and order boot so the redirector starts before the agent. Block or manage QUIC (UDP/443) separately, because CONNECT carries TCP only.

### 3. Run DCP in the host network namespace

```bash
docker run -d \
  --name dcp-agent \
  --restart unless-stopped \
  --network host \
  -e DCP_CONNECTION_MODE=fallback-only \
  -v /etc/dcp-agent/secrets/dcp-bootstrap-token:/etc/dcp-agent/secrets/dcp-bootstrap-token:ro \
  snowflakedb/dcp-client:latest
```

**Why `fallback-only`:** In our tests, the direct relay candidates returned at bootstrap resolved to **private-range IP addresses**, which the RFC1918 exclusions above would send direct rather than through the proxy. The fallback relay uses a public hostname that is routed through the redirect. `fallback-only` keeps all relay traffic on that path. Snowflake documents the fallback path as a fully supported production path.

### 4. Verify

```bash
# Bootstrap / reachability check (exits after printing per-step JSON)
docker run --rm --network host -e DCP_CONNECTION_MODE=fallback-only -e DCP_METRICS_PORT= \
  -v /etc/dcp-agent/secrets/dcp-bootstrap-token:/etc/dcp-agent/secrets/dcp-bootstrap-token:ro \
  snowflakedb/dcp-client:latest --health-check

journalctl -u dcp-egress -f        # redsocks should log each tunnelled connection
curl -s 127.0.0.1:9092/ready       # agent readiness (loopback with host networking)
```

```sql
DESCRIBE DATA CONNECTIVITY PROXY <your_dcp_object>;   -- expect AGENT_HEALTH = HEALTHY
SELECT * FROM TABLE(INFORMATION_SCHEMA.DCP_CLIENT_EVENT_HISTORY(AGENT_ID => '<your_dcp_object>'))
ORDER BY occurred_at DESC;
```

A successful TCP `CONNECT` is not enough. Success means the agent completes mTLS bootstrap and Snowflake reports it as healthy.

### 5. If the proxy listener itself uses TLS

There are two TLS sessions: the optional outer one to the proxy, and the untouched inner DCP session. Place a client-mode `stunnel` between redsocks and the proxy:

```text
# /etc/stunnel/dcp-proxy.conf
foreground = yes
[corporate-https-proxy]
client = yes
accept = 127.0.0.1:1443
connect = 10.20.30.40:443
verifyChain = yes
CAfile = /etc/ssl/certs/ca-certificates.crt
checkHost = proxy.corp.example
sni = proxy.corp.example
sslVersionMin = TLSv1.2
```

Point redsocks at `ip = 127.0.0.1; port = 1443;`, and keep the real proxy IP excluded in the netfilter chain. Do not disable certificate verification. If the proxy uses a private CA, add that CA to stunnel's bundle. This only affects the outer connection, not DCP.

## Other ways to force a non-proxy-aware application through an HTTP proxy

| Option | How it works | Notes |
|---|---|---|
| **redsocks** (`type = http-connect`) | iptables `REDIRECT`. Recovers the original destination via `SO_ORIGINAL_DST` and issues `CONNECT <ip>:443`. | Mature and small. Sends the **IP**, not the hostname. Basic auth only. |
| **redsocks2** | Fork of redsocks with more proxy types and TPROXY support. | Similar caveats. Packaging varies by distribution. |
| **tun2socks** ([xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks)) | Creates a TUN device, and policy routing sends traffic into it. The proxy can be `http://host:port` (CONNECT) or SOCKS5. | Routing-based rather than nat-based, so it suits containers and namespaces. Needs `ip rule` and route-table setup, plus an exclusion for the proxy itself. |
| **gost** / **sing-box** / **Xray** / **clash-meta** in redirect/tproxy mode | Transparent inbound (`redirect` or `tproxy`) to an HTTP CONNECT outbound. Some can sniff TLS SNI and send `CONNECT <hostname>:443`. | Sniffing SNI addresses hostname-based proxy policies. Larger tools, so review the configuration carefully. |
| **iptables TPROXY + policy routing** | Mangle-table TPROXY keeps the original destination without NAT. Requires an `IP_TRANSPARENT`-aware listener. | Use with a TPROXY-capable redirector (redsocks2, sing-box, gost). |
| **Python raw-TLS bridge (this repo)** | iptables `REDIRECT` to `dcp_connect_bridge.py --mode tls`. It reads the TLS ClientHello SNI and sends `CONNECT <sni-hostname>:443`. | Standard library only, minimal and auditable. Uses the **hostname**. Requires SNI (DCP's public hostnames use SNI). Not hardened for production. |
| **proxychains-ng** / `LD_PRELOAD` | Hooks libc `connect()`. | Generally **not suitable** for DCP. The agent is a compiled binary that may not go through hookable libc calls, and it runs in a container. |
| **Firewall / proxy appliance "transparent proxy" mode** | The network appliance intercepts TCP/443 and forwards it to the proxy itself. | No VM changes. The appliance must not decrypt DCP traffic. |
| **Direct allow rule (supported path)** | Allow TCP/443 from the agent host to the DCP hostnames with a no-decrypt exception. | This is Snowflake's documented deployment. Consider it first. |

### Can plain routing or firewall rules alone do it?

No, not on their own. An HTTP proxy expects a `CONNECT` request, so something has to speak that protocol. Routing (`ip route`, `ip rule`) and netfilter (`REDIRECT`, `DNAT`, `TPROXY`) can only steer packets to a local component. That component (redsocks, tun2socks, the Python bridge) then performs the CONNECT. `DNAT` straight to the proxy port does not work, because the proxy receives a TLS ClientHello instead of an HTTP request.

### Hostname vs IP in CONNECT

- redsocks only knows the destination IP, so it sends `CONNECT 3.x.x.x:443`. That works if the proxy allows by IP or allows any destination on 443 for this VM.
- If the proxy policy is hostname-based (common with Bluecoat/Symantec, Zscaler, Squid ACLs), use an SNI-aware redirector instead: this repo's Python bridge, or sing-box/gost with sniffing. The TLS session is not modified either way. Only the CONNECT line differs.
- DCP hostnames resolve to cloud IPs that can change. IP-based proxy rules need regular maintenance. Hostname rules do not.

### Docker bridge networking instead of host networking

With the default bridge network, container traffic passes through `PREROUTING` rather than `OUTPUT`. You would add a corresponding rule such as:

```bash
sudo iptables -t nat -I PREROUTING 1 -i docker0 -p tcp --dport 443 -j DCP_HTTPS
```

The redirector must then listen on an address reachable from the bridge (not only `127.0.0.1`), and `route_localnet` or an explicit listen IP may be needed. Host networking on a dedicated VM is the simpler option.

## Python raw-TLS bridge in this repo

Files:

- `dcp_connect_bridge.py`: standard-library adapter with two modes.
  - `--mode tls`: transparent listener for iptables `REDIRECT`. It parses only the ClientHello to read SNI, sends `CONNECT <sni>:443`, forwards the original bytes unchanged, then relays in both directions. There is no TLS termination and no payload logging.
  - `--mode connect`: explicit HTTP CONNECT relay (local CONNECT to upstream CONNECT).
- `local_forward_proxy.py`: a tiny local CONNECT proxy, for testing without a corporate proxy.
- `test_dcp_connect_bridge.py`: unit and localhost integration tests.
- `run_local_bridge_demo.py`: self-contained demo of ClientHello preservation.

Run the tests:

```bash
python3 -m unittest -v test_dcp_connect_bridge.py
python3 run_local_bridge_demo.py
```

Reproduce the "real DCP TLS through CONNECT" check (replace the hostname with your account's `DCP_CONTROL_PLANE` host):

```bash
python3 local_forward_proxy.py --listen-host 127.0.0.1 --listen-port 18081 &
DCP_BRIDGE_PROXY_URL=http://127.0.0.1:18081 \
  python3 dcp_connect_bridge.py --mode tls --listen-host 127.0.0.1 --listen-port 18080 &

python3 - <<'PY'
import socket, ssl
host = "dcp.<org>-<account>.<region>.<cloud>.snowflake.com"
with socket.create_connection(("127.0.0.1", 18080), timeout=10) as raw:
    with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
        print("TLS through bridge + CONNECT proxy:", tls.version())
PY
kill %1 %2
```

To use the bridge on the VM instead of redsocks, run it as an unprivileged user on `127.0.0.1:12345` with `DCP_BRIDGE_PROXY_URL=http://<proxy>:<port>`, and keep the same iptables chain. Add `-m owner --uid-owner <bridge-user> -j RETURN` so the bridge's own proxy connection is not redirected.

Security properties of the bridge:

- Only port 443 targets are allowed by default.
- Header parsing is bounded, with connect and header timeouts.
- If the upstream proxy does not return 2xx, the bridge fails closed.
- Proxy credentials come only from `DCP_BRIDGE_PROXY_URL` and are never logged.
- If no SNI is present, the connection is rejected (`--raw-target` can pin a single destination).

## Open items before relying on this

- End-to-end validation against the customer's real proxy (bootstrap, certificate rotation, data path, connection-history telemetry).
- Proxy tunnel idle and maximum lifetime versus DCP's long-lived connections.
- Behaviour during proxy failover or restarts.
- A Snowflake support position for the specific deployment.

## License

MIT. See [LICENSE](LICENSE).
