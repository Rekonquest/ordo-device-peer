//! Reusable Ordo peer helpers for device applications.
//!
//! This crate is intended for apps that should be discoverable as Ordo peers:
//! NVRs, camera tools, device agents, local services, and small companion apps.
//! It builds official `ordo_protocol::PeerPresence` records and can gather ICE
//! connectivity through `ordo_transport`, so every app advertises the same wire
//! shape Ordo already routes.

use std::{fs, net::SocketAddr, path::Path};

pub use ordo_protocol::{
    CryptoSuite, NatKind, NodeId, PairingMode, PeerPresence, TransportKind, TrustTier,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ORDO_PROTOCOL_VERSION: &str = "ordo/0.1";

#[derive(Debug, Error)]
pub enum DevicePeerError {
    #[error("peer label cannot be empty")]
    EmptyLabel,
    #[error("capability cannot be empty")]
    EmptyCapability,
    #[error("endpoint cannot be empty")]
    EmptyEndpoint,
    #[error("VPN control command cannot be empty")]
    EmptyCommand,
    #[error("VPN control failed: {0}")]
    VpnControl(String),
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePeerConfig {
    pub label: String,
    pub trust_tier: TrustTier,
    pub pairing_mode: PairingMode,
    pub nat_kind: NatKind,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default = "default_transports")]
    pub transports: Vec<TransportKind>,
    #[serde(default = "default_crypto_suites")]
    pub crypto_suites: Vec<CryptoSuite>,
}

impl DevicePeerConfig {
    pub fn builder(label: impl Into<String>) -> DevicePeerBuilder {
        DevicePeerBuilder::new(label)
    }

    pub fn into_presence(self) -> Result<PeerPresence, DevicePeerError> {
        validate_label(&self.label)?;
        validate_capabilities(&self.capabilities)?;
        validate_endpoints(&self.endpoints)?;

        Ok(PeerPresence {
            id: NodeId::new(),
            label: self.label,
            protocol_version: ORDO_PROTOCOL_VERSION.to_string(),
            trust_tier: self.trust_tier,
            pairing_mode: self.pairing_mode,
            nat_kind: self.nat_kind,
            transports: self.transports,
            crypto_suites: self.crypto_suites,
            endpoints: self.endpoints,
            capabilities: self.capabilities,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DevicePeerBuilder {
    config: DevicePeerConfig,
}

impl DevicePeerBuilder {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            config: DevicePeerConfig {
                label: label.into(),
                trust_tier: TrustTier::UnknownPeer,
                pairing_mode: PairingMode::PairingRequired,
                nat_kind: NatKind::Unknown,
                capabilities: Vec::new(),
                endpoints: Vec::new(),
                transports: default_transports(),
                crypto_suites: default_crypto_suites(),
            },
        }
    }

    pub fn trust_tier(mut self, trust_tier: TrustTier) -> Self {
        self.config.trust_tier = trust_tier;
        self
    }

    pub fn pairing_mode(mut self, pairing_mode: PairingMode) -> Self {
        self.config.pairing_mode = pairing_mode;
        self
    }

    pub fn nat_kind(mut self, nat_kind: NatKind) -> Self {
        self.config.nat_kind = nat_kind;
        self
    }

    pub fn capability(mut self, capability: impl Into<String>) -> Self {
        self.config.capabilities.push(capability.into());
        self
    }

    pub fn capabilities<I, S>(mut self, capabilities: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config
            .capabilities
            .extend(capabilities.into_iter().map(Into::into));
        self
    }

    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.config.endpoints.push(endpoint.into());
        self
    }

    pub fn quic_endpoint(mut self, address: SocketAddr, fingerprint: Option<&str>) -> Self {
        let endpoint = if let Some(fingerprint) = fingerprint {
            format!("quic://{address}#sha256:{fingerprint}")
        } else {
            format!("quic+insecure://{address}")
        };
        self.config.endpoints.push(endpoint);
        self
    }

    pub fn transports(mut self, transports: Vec<TransportKind>) -> Self {
        self.config.transports = transports;
        self
    }

    pub fn crypto_suites(mut self, crypto_suites: Vec<CryptoSuite>) -> Self {
        self.config.crypto_suites = crypto_suites;
        self
    }

    pub fn build(self) -> Result<PeerPresence, DevicePeerError> {
        self.config.into_presence()
    }
}

pub fn load_presence(path: impl AsRef<Path>) -> Result<PeerPresence, DevicePeerError> {
    let body = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&body)?)
}

pub fn save_presence(
    path: impl AsRef<Path>,
    presence: &PeerPresence,
) -> Result<(), DevicePeerError> {
    let body = serde_json::to_string_pretty(presence)?;
    fs::write(path, body)?;
    Ok(())
}

pub fn presence_json(presence: &PeerPresence) -> Result<String, DevicePeerError> {
    Ok(serde_json::to_string_pretty(presence)?)
}

pub fn default_transports() -> Vec<TransportKind> {
    vec![
        TransportKind::Quic,
        TransportKind::TcpNoise,
        TransportKind::RelayQuic,
    ]
}

pub fn default_crypto_suites() -> Vec<CryptoSuite> {
    vec![CryptoSuite::HybridPqNoiseX25519, CryptoSuite::NoiseX25519]
}

pub mod imperium_vpn {
    use super::*;

    pub const CAP_CLUSTER_STATUS: &str = "vpn.cluster.status";
    pub const CAP_SIGNATURES_PENDING: &str = "vpn.signatures.pending";
    pub const CAP_SIGNATURE_APPROVE: &str = "vpn.signatures.approve";
    pub const CAP_SIGNATURE_REJECT: &str = "vpn.signatures.reject";
    pub const CAP_SIGNATURE_EXTRACT: &str = "vpn.signatures.extract";
    pub const CAP_SIGNATURE_SHOW: &str = "vpn.signatures.show";
    pub const CAP_SHUTDOWN: &str = "vpn.shutdown";
    pub const CAP_HEALTH: &str = "vpn.health";
    pub const CAP_PROFILE_ROTATE: &str = "vpn.profile.rotate";
    pub const CAP_TRANSPORT_SET_ACTIVE: &str = "vpn.transport.set_active";
    pub const CAP_POLICY_APPLY: &str = "vpn.policy.apply";
    pub const CAP_NAT_AGGRESSIVE: &str = "vpn.nat.aggressive";
    pub const CAP_KILLSWITCH: &str = "vpn.killswitch";
    pub const CAP_MASQUE_CONFIGURE: &str = "vpn.masque.configure";
    pub const CAP_TOOLKIT_ACTIVATE: &str = "vpn.toolkit.activate";
    pub const CAP_HARDENING_PRESET: &str = "vpn.hardening.preset";
    pub const CAP_HARDENING_APPLY: &str = "vpn.hardening.apply";
    pub const CAP_DEPLOYMENT_APPLY: &str = "vpn.deployment.apply";
    pub const CAP_DEPLOYMENT_STATUS: &str = "vpn.deployment.status";

    pub const DEFAULT_IMPERIUM_CONTROL_PIPE: &str = r"\\.\pipe\imperium-control";

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum VpnControlCommand {
        Health,
        ProfileRotate {
            protocol_name: Option<String>,
        },
        TransportSetActive {
            protocol_name: String,
        },
        PolicyApply {
            policy_id: String,
        },
        NatAggressive {
            enabled: bool,
        },
        KillSwitch {
            state: String,
            reason: Option<String>,
        },
        MasqueConfigure {
            config_json: String,
        },
        HardeningPreset {
            preset: String,
            protocol_name: Option<String>,
        },
        HardeningApply {
            profile_json: String,
        },
        ToolkitActivate {
            tool_name: String,
            trigger: Option<String>,
        },
        DeploymentApply {
            plan_json: String,
        },
        DeploymentStatus,
        ClusterStatus,
        SignaturesPending,
        SignatureApprove {
            candidate_id: String,
        },
        SignatureReject {
            candidate_id: String,
            reason: Option<String>,
        },
        SignatureExtract {
            event_ids: Vec<String>,
        },
        SignatureShow {
            candidate_id: String,
        },
        Shutdown,
    }

    impl VpnControlCommand {
        pub fn to_imperium_line(&self) -> Result<String, DevicePeerError> {
            match self {
                Self::Health => Ok("vpn health".to_string()),
                Self::ProfileRotate { protocol_name } => {
                    if let Some(protocol_name) = protocol_name {
                        validate_nonempty(protocol_name)?;
                        Ok(format!("vpn profile rotate {protocol_name}"))
                    } else {
                        Ok("vpn profile rotate".to_string())
                    }
                }
                Self::TransportSetActive { protocol_name } => {
                    validate_nonempty(protocol_name)?;
                    Ok(format!("vpn transport set-active {protocol_name}"))
                }
                Self::PolicyApply { policy_id } => {
                    validate_nonempty(policy_id)?;
                    Ok(format!("vpn policy apply {policy_id}"))
                }
                Self::NatAggressive { enabled } => Ok(format!(
                    "vpn nat aggressive {}",
                    if *enabled { "on" } else { "off" }
                )),
                Self::KillSwitch { state, reason } => {
                    validate_nonempty(state)?;
                    if let Some(reason) = reason {
                        validate_nonempty(reason)?;
                        Ok(format!("vpn killswitch {state} {reason}"))
                    } else {
                        Ok(format!("vpn killswitch {state}"))
                    }
                }
                Self::MasqueConfigure { config_json } => {
                    validate_nonempty(config_json)?;
                    Ok(format!("vpn masque configure {config_json}"))
                }
                Self::HardeningPreset {
                    preset,
                    protocol_name,
                } => {
                    validate_nonempty(preset)?;
                    if let Some(protocol_name) = protocol_name {
                        validate_nonempty(protocol_name)?;
                        Ok(format!("vpn hardening preset {preset} {protocol_name}"))
                    } else {
                        Ok(format!("vpn hardening preset {preset}"))
                    }
                }
                Self::HardeningApply { profile_json } => {
                    validate_nonempty(profile_json)?;
                    Ok(format!("vpn hardening apply {profile_json}"))
                }
                Self::ToolkitActivate { tool_name, trigger } => {
                    validate_nonempty(tool_name)?;
                    if let Some(trigger) = trigger {
                        validate_nonempty(trigger)?;
                        Ok(format!("vpn toolkit activate {tool_name} {trigger}"))
                    } else {
                        Ok(format!("vpn toolkit activate {tool_name}"))
                    }
                }
                Self::DeploymentApply { plan_json } => {
                    validate_nonempty(plan_json)?;
                    Ok(format!("vpn deployment apply {plan_json}"))
                }
                Self::DeploymentStatus => Ok("vpn deployment status".to_string()),
                Self::ClusterStatus => Ok("cluster status".to_string()),
                Self::SignaturesPending => Ok("signatures pending".to_string()),
                Self::SignatureApprove { candidate_id } => {
                    validate_nonempty(candidate_id)?;
                    Ok(format!("signatures approve {candidate_id}"))
                }
                Self::SignatureReject {
                    candidate_id,
                    reason,
                } => {
                    validate_nonempty(candidate_id)?;
                    if let Some(reason) = reason {
                        validate_nonempty(reason)?;
                        Ok(format!("signatures reject {candidate_id} {reason}"))
                    } else {
                        Ok(format!("signatures reject {candidate_id}"))
                    }
                }
                Self::SignatureExtract { event_ids } => {
                    if event_ids.is_empty() || event_ids.iter().any(|id| id.trim().is_empty()) {
                        return Err(DevicePeerError::EmptyCommand);
                    }
                    Ok(format!("signatures extract {}", event_ids.join(",")))
                }
                Self::SignatureShow { candidate_id } => {
                    validate_nonempty(candidate_id)?;
                    Ok(format!("signatures show {candidate_id}"))
                }
                Self::Shutdown => Ok("shutdown".to_string()),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct VpnControlResponse {
        pub raw_json: String,
    }

    #[derive(Debug, Clone)]
    pub struct ImperiumControlClient {
        pipe_name: String,
    }

    impl Default for ImperiumControlClient {
        fn default() -> Self {
            Self::new(DEFAULT_IMPERIUM_CONTROL_PIPE)
        }
    }

    impl ImperiumControlClient {
        pub fn new(pipe_name: impl Into<String>) -> Self {
            Self {
                pipe_name: pipe_name.into(),
            }
        }

        pub fn execute(
            &self,
            command: &VpnControlCommand,
        ) -> Result<VpnControlResponse, DevicePeerError> {
            let line = command.to_imperium_line()?;
            let raw_json = send_control_line(&self.pipe_name, &line)?;
            Ok(VpnControlResponse { raw_json })
        }
    }

    pub fn capabilities() -> [&'static str; 19] {
        [
            CAP_HEALTH,
            CAP_PROFILE_ROTATE,
            CAP_TRANSPORT_SET_ACTIVE,
            CAP_POLICY_APPLY,
            CAP_NAT_AGGRESSIVE,
            CAP_KILLSWITCH,
            CAP_MASQUE_CONFIGURE,
            CAP_HARDENING_PRESET,
            CAP_HARDENING_APPLY,
            CAP_TOOLKIT_ACTIVATE,
            CAP_DEPLOYMENT_APPLY,
            CAP_DEPLOYMENT_STATUS,
            CAP_CLUSTER_STATUS,
            CAP_SIGNATURES_PENDING,
            CAP_SIGNATURE_APPROVE,
            CAP_SIGNATURE_REJECT,
            CAP_SIGNATURE_EXTRACT,
            CAP_SIGNATURE_SHOW,
            CAP_SHUTDOWN,
        ]
    }

    pub fn builder(label: impl Into<String>) -> DevicePeerBuilder {
        DevicePeerConfig::builder(label)
            .trust_tier(TrustTier::PairedPeer)
            .pairing_mode(PairingMode::PairingRequired)
            .capabilities(capabilities())
    }

    pub fn presence(label: impl Into<String>) -> Result<PeerPresence, DevicePeerError> {
        builder(label).build()
    }

    fn validate_nonempty(value: &str) -> Result<(), DevicePeerError> {
        if value.trim().is_empty() {
            Err(DevicePeerError::EmptyCommand)
        } else {
            Ok(())
        }
    }

    #[cfg(windows)]
    fn send_control_line(pipe_name: &str, line: &str) -> Result<String, DevicePeerError> {
        use std::fs::OpenOptions;
        use std::io::{BufRead, BufReader, Write};

        let mut pipe = OpenOptions::new().read(true).write(true).open(pipe_name)?;
        let reader_pipe = pipe.try_clone()?;
        writeln!(pipe, "{line}")?;
        pipe.flush()?;

        let mut reader = BufReader::new(reader_pipe);
        let mut response = String::new();
        reader.read_line(&mut response)?;
        Ok(response.trim_end().to_string())
    }

    #[cfg(not(windows))]
    fn send_control_line(_pipe_name: &str, _line: &str) -> Result<String, DevicePeerError> {
        Err(DevicePeerError::VpnControl(
            "Imperium control pipe client is currently implemented for Windows".to_string(),
        ))
    }
}

fn validate_label(label: &str) -> Result<(), DevicePeerError> {
    if label.trim().is_empty() {
        Err(DevicePeerError::EmptyLabel)
    } else {
        Ok(())
    }
}

fn validate_capabilities(capabilities: &[String]) -> Result<(), DevicePeerError> {
    if capabilities
        .iter()
        .any(|capability| capability.trim().is_empty())
    {
        Err(DevicePeerError::EmptyCapability)
    } else {
        Ok(())
    }
}

fn validate_endpoints(endpoints: &[String]) -> Result<(), DevicePeerError> {
    if endpoints.iter().any(|endpoint| endpoint.trim().is_empty()) {
        Err(DevicePeerError::EmptyEndpoint)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_nvr_peer_presence() {
        let peer = DevicePeerConfig::builder("garage-nvr")
            .nat_kind(NatKind::Cone)
            .capabilities([
                "nvr.camera.list",
                "nvr.camera.snapshot",
                "nvr.recording.search",
            ])
            .endpoint("quic+insecure://127.0.0.1:4141")
            .build()
            .expect("presence");

        assert_eq!(peer.label, "garage-nvr");
        assert!(peer
            .transports
            .iter()
            .any(|transport| matches!(transport, TransportKind::TcpNoise)));
        assert!(peer
            .crypto_suites
            .iter()
            .any(|suite| matches!(suite, CryptoSuite::HybridPqNoiseX25519)));
        assert_eq!(peer.capabilities.len(), 3);
    }

    #[test]
    fn save_and_load_presence_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("peer.json");
        let peer = DevicePeerConfig::builder("nvr")
            .capability("nvr.camera.list")
            .build()
            .expect("presence");

        save_presence(&path, &peer).expect("save");
        let loaded = load_presence(&path).expect("load");

        assert_eq!(loaded.label, "nvr");
        assert_eq!(loaded.capabilities, vec!["nvr.camera.list".to_string()]);
    }

    #[test]
    fn rejects_empty_capabilities() {
        let err = DevicePeerConfig::builder("nvr")
            .capability("")
            .build()
            .expect_err("empty capability");

        assert!(matches!(err, DevicePeerError::EmptyCapability));
    }

    #[test]
    fn builds_imperium_vpn_presence() {
        let peer = imperium_vpn::presence("imperium-vpn").expect("presence");

        assert_eq!(peer.label, "imperium-vpn");
        assert!(peer
            .capabilities
            .contains(&imperium_vpn::CAP_CLUSTER_STATUS.to_string()));
        assert!(peer
            .capabilities
            .contains(&imperium_vpn::CAP_SHUTDOWN.to_string()));
        assert!(peer
            .capabilities
            .contains(&imperium_vpn::CAP_NAT_AGGRESSIVE.to_string()));
        assert!(peer
            .capabilities
            .contains(&imperium_vpn::CAP_TOOLKIT_ACTIVATE.to_string()));
        assert!(peer
            .capabilities
            .contains(&imperium_vpn::CAP_HARDENING_PRESET.to_string()));
        assert!(peer
            .capabilities
            .contains(&imperium_vpn::CAP_DEPLOYMENT_APPLY.to_string()));
        assert!(peer
            .capabilities
            .contains(&imperium_vpn::CAP_DEPLOYMENT_STATUS.to_string()));
    }

    #[test]
    fn maps_vpn_commands_to_imperium_control_lines() {
        let approve = imperium_vpn::VpnControlCommand::SignatureApprove {
            candidate_id: "abc".to_string(),
        };
        assert_eq!(
            approve.to_imperium_line().unwrap(),
            "signatures approve abc"
        );

        let extract = imperium_vpn::VpnControlCommand::SignatureExtract {
            event_ids: vec!["a".to_string(), "b".to_string()],
        };
        assert_eq!(
            extract.to_imperium_line().unwrap(),
            "signatures extract a,b"
        );

        let nat = imperium_vpn::VpnControlCommand::NatAggressive { enabled: true };
        assert_eq!(nat.to_imperium_line().unwrap(), "vpn nat aggressive on");

        let toolkit = imperium_vpn::VpnControlCommand::ToolkitActivate {
            tool_name: "transport.diagnostics".to_string(),
            trigger: Some("manual check".to_string()),
        };
        assert_eq!(
            toolkit.to_imperium_line().unwrap(),
            "vpn toolkit activate transport.diagnostics manual check"
        );

        let hardening = imperium_vpn::VpnControlCommand::HardeningPreset {
            preset: "balanced".to_string(),
            protocol_name: Some("masque".to_string()),
        };
        assert_eq!(
            hardening.to_imperium_line().unwrap(),
            "vpn hardening preset balanced masque"
        );

        let fortress = imperium_vpn::VpnControlCommand::HardeningPreset {
            preset: "fortress".to_string(),
            protocol_name: Some("xray".to_string()),
        };
        assert_eq!(
            fortress.to_imperium_line().unwrap(),
            "vpn hardening preset fortress xray"
        );

        let rotate = imperium_vpn::VpnControlCommand::ProfileRotate {
            protocol_name: Some("masque".to_string()),
        };
        assert_eq!(
            rotate.to_imperium_line().unwrap(),
            "vpn profile rotate masque"
        );

        let deploy = imperium_vpn::VpnControlCommand::DeploymentApply {
            plan_json: r#"{"deployment_id":"00000000-0000-0000-0000-000000000000"}"#.to_string(),
        };
        assert_eq!(
            deploy.to_imperium_line().unwrap(),
            r#"vpn deployment apply {"deployment_id":"00000000-0000-0000-0000-000000000000"}"#
        );

        assert_eq!(
            imperium_vpn::VpnControlCommand::DeploymentStatus
                .to_imperium_line()
                .unwrap(),
            "vpn deployment status"
        );
    }
}
