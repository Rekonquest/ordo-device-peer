# ordo-device-peer

Reusable Rust crate for apps that should connect to Ordo as local devices.

Use this in apps like an NVR, camera service, local sensor agent, or companion
tool so each app can advertise the same peer shape Ordo already routes:

- `PeerPresence`
- `Quic`, `TcpNoise`, and `RelayQuic` transports
- hybrid PQ/Noise crypto suites
- NAT kind
- app-specific capabilities

The crate intentionally does not own your app protocol. Your app still decides
what `nvr.camera.snapshot` or `nvr.recording.search` does. This crate only makes
the app visible to Ordo as a direct-connect peer.

## Example

```rust
use ordo_device_peer::{presence_json, DevicePeerConfig, NatKind};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let peer = DevicePeerConfig::builder("garage-nvr")
        .nat_kind(NatKind::Cone)
        .capabilities([
            "nvr.camera.list",
            "nvr.camera.snapshot",
            "nvr.recording.search",
        ])
        .endpoint("quic+insecure://127.0.0.1:4141")
        .build()?;

    println!("{}", presence_json(&peer)?);
    Ok(())
}
```

## Imperium VPN Control

The crate also includes an `imperium_vpn` adapter for advertising an Imperium
VPN control peer to Ordo:

```rust
use ordo_device_peer::{imperium_vpn, presence_json};

let peer = imperium_vpn::builder("imperium-vpn")
    .endpoint("tcp+noise://127.0.0.1:4142")
    .build()?;

println!("{}", presence_json(&peer)?);
```

It advertises capabilities such as `vpn.health`, `vpn.profile.rotate`,
`vpn.transport.set_active`, `vpn.nat.aggressive`, `vpn.killswitch`,
`vpn.masque.configure`, `vpn.hardening.preset`, `vpn.hardening.apply`,
`vpn.deployment.apply`, `vpn.deployment.status`, `vpn.toolkit.activate`,
`vpn.shutdown`, and `vpn.signatures.extract`. The local adapter maps typed
`VpnControlCommand` values to Imperium's control surface at
`\\.\pipe\imperium-control`.

Deployment management is exposed through:

```rust
use ordo_device_peer::imperium_vpn::VpnControlCommand;

let apply = VpnControlCommand::DeploymentApply {
    plan_json: r#"{"deployment_id":"00000000-0000-0000-0000-000000000000","cluster_id":null,"nodes":[{"label":"operator","role":"Operator","peer_id":null,"endpoint":"127.0.0.1:32000","capabilities":["vpn.cluster.admin"]},{"label":"client-a","role":"Client","peer_id":null,"endpoint":"127.0.0.1:32001","capabilities":["vpn.client"]},{"label":"relay-a","role":"Relay","peer_id":null,"endpoint":"127.0.0.1:32002","capabilities":["vpn.relay"]}],"hardening_preset":"fortress","nat_aggressive":false,"relay_auto":true,"config_blob":[123,125],"requested_by":"ordo","requested_at":"2026-06-02T00:00:00Z"}"#.to_string(),
};
let status = VpnControlCommand::DeploymentStatus;
```

Ordo's intended fallback ladder is:

1. direct QUIC
2. TCP Noise
3. Ordo relay

Cloud LLM/provider connections are separate and still go through Ordo's normal
provider credential layer.

## License

Licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE) (`PolyForm-Noncommercial-1.0.0`). Free for personal use, research, education, charities, public-good nonprofits, and government; commercial use is not permitted. This is source-available software, not OSI open source.
