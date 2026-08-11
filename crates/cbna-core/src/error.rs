use std::fmt;

/// Errors produced while decoding a single layer.
///
/// Decode failures are expected on real traffic (snaplen truncation, malformed
/// frames, protocols we do not model) so they are cheap, `Copy`-ish values that
/// callers usually record as a warning rather than propagate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("{layer}: truncated, need {need} bytes but only {have} remain")]
    Truncated {
        layer: &'static str,
        need: usize,
        have: usize,
    },

    #[error("{layer}: unsupported value {value:#x}")]
    Unsupported { layer: &'static str, value: u64 },

    #[error("{layer}: malformed ({reason})")]
    Malformed {
        layer: &'static str,
        reason: &'static str,
    },
}

impl DecodeError {
    pub fn malformed(layer: &'static str, reason: &'static str) -> Self {
        Self::Malformed { layer, reason }
    }

    pub fn unsupported(layer: &'static str, value: impl Into<u64>) -> Self {
        Self::Unsupported {
            layer,
            value: value.into(),
        }
    }

    /// Layer name the failure was attributed to, for grouping warnings.
    pub fn layer(&self) -> &'static str {
        match self {
            Self::Truncated { layer, .. }
            | Self::Unsupported { layer, .. }
            | Self::Malformed { layer, .. } => layer,
        }
    }
}

pub type Result<T> = std::result::Result<T, DecodeError>;

/// Wrapper used when a decode failure should be reported but not fatal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning(pub String);

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<DecodeError> for Warning {
    fn from(e: DecodeError) -> Self {
        Warning(e.to_string())
    }
}
