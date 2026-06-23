use ordo_device_peer::{imperium_vpn, presence_json};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let peer = imperium_vpn::builder("imperium-vpn")
        .endpoint("tcp+noise://127.0.0.1:4142")
        .build()?;

    println!("{}", presence_json(&peer)?);
    Ok(())
}
