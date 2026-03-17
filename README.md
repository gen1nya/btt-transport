# BTT Transport

Encrypted UDP transport over uTP with optional relay support.

## Build

```bash
go build ./cmd/server
go build ./cmd/client
go build ./cmd/relay
```

Cross-compile for Linux:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o btt-server ./cmd/server
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o btt-client ./cmd/client
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o btt-relay  ./cmd/relay
```

## Server

Listens for incoming connections and forwards decrypted UDP to a target address.

```bash
btt-server \
  -listen 0.0.0.0:6881 \
  -psk "secret-key" \
  -forward-udp 127.0.0.1:51820 \
  -transport utp \
  -camouflage \
  -dht
```

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `0.0.0.0:6881` | Listen address |
| `-psk` | `test-psk-2026` | Pre-shared key |
| `-forward-udp` | _(none)_ | Forward decrypted UDP to this address. If omitted, runs in echo mode |
| `-transport` | `utp` | Transport protocol: `utp` or `tcp` |
| `-camouflage` | `false` | Enable protocol handshake and padded framing |
| `-dht` | `false` | Announce via DHT |

## Client

Connects to server and proxies local UDP traffic through the encrypted tunnel.

```bash
btt-client \
  -server 1.2.3.4:6881 \
  -psk "secret-key" \
  -mode udp-proxy \
  -listen-udp 127.0.0.1:51821 \
  -transport utp \
  -camouflage
```

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | _(none)_ | Server address. If omitted with `-dht`, discovered automatically |
| `-psk` | `test-psk-2026` | Pre-shared key |
| `-mode` | `echo` | Mode: `echo`, `bench`, `udp-proxy` |
| `-listen-udp` | `0.0.0.0:51821` | Local UDP listen address (for `udp-proxy` mode) |
| `-transport` | `utp` | Transport protocol: `utp` or `tcp` |
| `-camouflage` | `false` | Enable protocol handshake and padded framing |
| `-dht` | `false` | Discover server via DHT |

Auto-reconnects with exponential backoff (1s to 30s). The UDP listener persists across reconnections.

### Test modes

```bash
# Echo — connectivity check
btt-client -server 1.2.3.4:6881 -psk test -mode echo

# Bandwidth benchmark (100 MB)
btt-client -server 1.2.3.4:6881 -psk test -mode bench -camouflage
```

## Relay

Transparent byte-level forwarder. Does not decrypt traffic — encryption is end-to-end between client and server.

```bash
# Direct server address
btt-relay -server 1.2.3.4:6881 -psk "secret-key"

# With UPnP (behind NAT)
btt-relay -server 1.2.3.4:6881 -psk "secret-key" -upnp

# With DHT (auto-discover server + announce as relay)
btt-relay -psk "secret-key" -dht -upnp
```

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `0.0.0.0:6881` | Listen address |
| `-psk` | `test-psk-2026` | Pre-shared key |
| `-server` | _(none)_ | Server address. If omitted with `-dht`, discovered automatically |
| `-dht` | `false` | Announce as relay and discover server via DHT |
| `-upnp` | `false` | Open port via UPnP for NAT traversal |

## Deploy

```bash
sudo cp btt-server /usr/local/bin/
sudo cp deploy/btt-server.service /etc/systemd/system/
sudo mkdir -p /etc/btt
echo 'BTT_PSK=your-secret-key' | sudo tee /etc/btt/server.env
sudo systemctl enable --now btt-server
```

```bash
sudo cp btt-client /usr/local/bin/
sudo cp deploy/btt-client.service /etc/systemd/system/
echo -e 'BTT_SERVER=1.2.3.4:6881\nBTT_PSK=your-secret-key' | sudo tee /etc/btt/client.env
sudo systemctl enable --now btt-client
```
