//! Wire error type. Stable across transports.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "error_type", rename_all = "snake_case")]
pub enum RpcError {
    #[error("validation failed: {message}")]
    Validation { message: String },
    #[error("entity already exists: {kind} {id}")]
    AlreadyExists { kind: String, id: String },
    #[error("not found: {kind} {id}")]
    NotFound { kind: String, id: String },
    #[error("provisioning failed at stage '{stage}': {reason}")]
    ProvisioningFailed { stage: String, reason: String },
    #[error("system command failed: {cmd} exit {code}")]
    SystemCommand {
        cmd: String,
        code: i32,
        stderr_tail: String,
    },
    #[error("conflict: {message}")]
    Conflict { message: String },
    #[error("internal error")]
    Internal,
}

impl From<lm_validate::ValidationError> for RpcError {
    fn from(e: lm_validate::ValidationError) -> Self {
        Self::Validation {
            message: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_variant_round_trips() {
        let cases = vec![
            RpcError::Validation { message: "m".into() },
            RpcError::AlreadyExists {
                kind: "k".into(),
                id: "i".into(),
            },
            RpcError::NotFound {
                kind: "k".into(),
                id: "i".into(),
            },
            RpcError::ProvisioningFailed {
                stage: "s".into(),
                reason: "r".into(),
            },
            RpcError::SystemCommand {
                cmd: "c".into(),
                code: 1,
                stderr_tail: "e".into(),
            },
            RpcError::Conflict { message: "c".into() },
            RpcError::Internal,
        ];
        for c in cases {
            let s = serde_json::to_string(&c).expect("serialize");
            let back: RpcError = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(c, back);
        }
    }

    #[test]
    fn from_validation_error_maps_to_validation_variant() {
        let e: RpcError =
            lm_validate::ValidationError::InvalidDomain("x".into(), "bad").into();
        match e {
            RpcError::Validation { .. } => {}
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn display_matches_thiserror_message() {
        let e = RpcError::NotFound {
            kind: "hosting".into(),
            id: "abc".into(),
        };
        assert_eq!(e.to_string(), "not found: hosting abc");
    }
}
