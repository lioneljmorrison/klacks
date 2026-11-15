# Architecture

How the pieces of klacks fit together. Arrows are real package imports or
network calls; dotted arrows are configuration, logging or "speaks the same
format".

```mermaid
flowchart TB
    %% ---------- Clients ----------
    subgraph Clients["Client side (all crypto happens here)"]
        direction TB
        RefClient["client/<br/>Go reference E2EE impl<br/>X3DH · Double Ratchet · Sender Keys<br/>Ed25519 / X25519 / HKDF / ChaCha20-Poly1305"]
        Apps["Client apps<br/>(any lib speaking the wire format)"]
    end

    %% ---------- Embedders ----------
    subgraph Embed["Embedding (in-process)"]
        Example["examples/meetings<br/>toy meeting scheduler"]
        PkgChat["pkg/chat<br/>public ChatService<br/>CreateRoom · AddMember · RemoveMember<br/>PostMessage · Subscribe"]
    end

    %% ---------- Server binary ----------
    subgraph Server["cmd/klacks — serve · migrate · config"]
        direction TB
        subgraph Transports["internal/api"]
            HTTP["httpapi<br/>GET /healthz · /readyz<br/>PUT /v1/device/bundle<br/>POST /v1/device/prekeys<br/>GET /v1/users/{u}/devices[/{d}/bundle]"]
            WS["ws<br/>GET /ws — live chat"]
            GRPC["grpcapi<br/>klacks.chat.v1.ChatService<br/>(service tokens)"]
        end
        Auth["internal/auth"]
        Protocol["internal/protocol<br/>wire frames"]
        Core["internal/core<br/>rooms · authz · sequencing<br/>fan-out · resume"]
        Store["internal/store<br/>rooms · devices · messages"]
        Migrate["internal/store/migrate"]
        Config["internal/config"]
        Logging["internal/logging (slog)"]
    end

    Proto["api/proto → api/gen<br/>chat.proto (buf)"]
    Migrations["migrations/ (embedded)"]

    %% ---------- Datastores ----------
    subgraph Data["Datastores (docker compose)"]
        PG[("PostgreSQL<br/>rooms · devices · seq<br/>prekey bundles")]
        Scylla[("ScyllaDB<br/>messages (ciphertext)")]
    end

    %% ---------- Edges ----------
    Apps -. "same wire format" .- RefClient
    RefClient -- "REST: register / fetch bundles" --> HTTP
    RefClient -- "WebSocket: ciphertext envelopes" --> WS
    RefClient -. "uses" .-> Protocol

    Example --> PkgChat
    PkgChat --> Core
    GRPC --> PkgChat
    GRPC --> Proto

    HTTP --> Auth
    HTTP --> Store
    HTTP -- "mounts /ws" --> WS
    WS --> Auth
    WS --> Protocol
    WS --> Core
    Protocol --> Core
    Auth --> Store
    Core --> Store

    Store --> PG
    Store --> Scylla
    Migrate --> Migrations
    Migrate --> PG
    Migrate --> Scylla

    Config -.-> Store
    Config -.-> HTTP
    Config -.-> PkgChat
    Logging -.-> Server
```

- **The server never sees plaintext.** Only `client/` (and real client apps)
  encrypt and decrypt. The server stores and relays ciphertext. Both sides
  speak the [klacks wire protocol](protocol.md).
- **Three ways in.** Over the network, clients use `httpapi` for prekey
  bundles and `ws` for messages. Embedders call `pkg/chat` in-process, or
  its gRPC mirror (`grpcapi`) from another process. All paths end in
  `internal/core`.
- **Split storage.** PostgreSQL holds rooms, devices, sequence numbers and
  prekey bundles. ScyllaDB holds messages.
- **One core, two transports.** With `grpc.addr` set, `serve` runs the gRPC
  API next to HTTP over the same core: its fan-out and member removals reach
  both the WebSocket hub and the gRPC subscriptions, so each transport sees
  the other's messages live.

Test-only packages (`internal/testutil/dbtest`) are left out.
