use ordo_device_peer::{presence_json, DevicePeerConfig, NatKind};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let peer = DevicePeerConfig::builder("garage-nvr")
        .nat_kind(NatKind::Cone)
        .capabilities([
            "nvr.camera.list",
            "nvr.camera.snapshot",
            "nvr.recording.search",
            "nvr.recording.export_clip",
        ])
        .endpoint("quic+insecure://127.0.0.1:4141")
        .build()?;

    println!("{}", presence_json(&peer)?);
    Ok(())
}
