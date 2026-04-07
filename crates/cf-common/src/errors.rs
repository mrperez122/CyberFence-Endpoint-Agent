//! Unified error type for the CyberFence agent.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CfError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Watcher error: {0}")]
    Watcher(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Channel send error: {0}")]
    ChannelSend(String),

    #[error("Shutdown requested")]
    Shutdown,
}
