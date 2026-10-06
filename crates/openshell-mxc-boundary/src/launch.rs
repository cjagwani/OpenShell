// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MXC-owned host launch data, separate from the shared Sandbox Protocol.

use openshell_isolation_interface::contract::BackendError;
use openshell_sandbox_backend::boundary_protocol::{BoundaryConfig, SandboxRuntimeDescriptor};
use serde::{Deserialize, Serialize};
use std::{fmt, net::SocketAddr, path::PathBuf};

/// Protected, generation-bound launch envelope decoded by Windows composition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MxcLaunchDescriptor {
    pub runtime: SandboxRuntimeDescriptor,
    pub proxy: MxcProxyConfig,
}

/// One-use Windows bootstrap; proxy credentials are never in shared protocol data.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MxcBoundaryConfig {
    pub runtime: BoundaryConfig,
    pub proxy_url: String,
}

impl MxcBoundaryConfig {
    pub fn encode(&self) -> Result<Vec<u8>, BackendError> {
        serde_json::to_vec(self)
            .map_err(|e| BackendError::Descriptor(format!("encode MXC bootstrap: {e}")))
    }
}

impl fmt::Debug for MxcBoundaryConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MxcBoundaryConfig")
            .field("runtime", &self.runtime)
            .field("proxy_url", &"<redacted>")
            .finish()
    }
}

/// Only MXC needs to provision an authenticated host CONNECT listener.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MxcProxyConfig {
    pub bind_addr: SocketAddr,
    pub authorization: String,
    pub workload_binary: PathBuf,
}

impl fmt::Debug for MxcProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MxcProxyConfig")
            .field("bind_addr", &self.bind_addr)
            .field("authorization", &"<redacted>")
            .field("workload_binary", &self.workload_binary)
            .finish()
    }
}

impl MxcLaunchDescriptor {
    pub fn decode(payload: &[u8]) -> Result<Self, BackendError> {
        let descriptor: Self = serde_json::from_slice(payload)
            .map_err(|e| BackendError::Descriptor(format!("decode MXC launch data: {e}")))?;
        descriptor.proxy.validate()?;
        Ok(descriptor)
    }
}

impl MxcProxyConfig {
    pub fn validate(&self) -> Result<(), BackendError> {
        if !self.bind_addr.ip().is_loopback()
            || self.bind_addr.port() == 0
            || self.authorization.trim().is_empty()
            || self.authorization.contains(['\r', '\n'])
            || !self.workload_binary.is_absolute()
        {
            return Err(BackendError::Descriptor(
                "MXC proxy requires a loopback listener, single-line authorization, and an absolute workload binary".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy() -> MxcProxyConfig {
        MxcProxyConfig {
            bind_addr: "127.0.0.1:3128".parse().unwrap(),
            authorization: "Basic generation-secret".into(),
            workload_binary: "C:/Windows/System32/cmd.exe".into(),
        }
    }

    #[test]
    fn proxy_configuration_is_validated_by_mxc() {
        assert!(proxy().validate().is_ok());
        for address in ["0.0.0.0:3128", "192.0.2.1:3128", "127.0.0.1:0"] {
            let mut config = proxy();
            config.bind_addr = address.parse().unwrap();
            assert!(config.validate().is_err());
        }
        for authorization in ["", " ", "Basic token\r\nInjected: header"] {
            let mut config = proxy();
            config.authorization = authorization.into();
            assert!(config.validate().is_err());
        }
        let mut config = proxy();
        config.workload_binary = "relative.exe".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn launch_credentials_are_redacted_and_unknown_fields_rejected() {
        assert!(!format!("{:?}", proxy()).contains("generation-secret"));
        let mut value = serde_json::to_value(proxy()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<MxcProxyConfig>(value).is_err());
        assert!(MxcLaunchDescriptor::decode(b"{}").is_err());
    }
}
