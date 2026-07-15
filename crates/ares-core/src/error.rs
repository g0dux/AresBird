use thiserror::Error;

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("invalid port spec: {0}")]
    InvalidPortSpec(String),
    #[error("job cancelled")]
    Cancelled,
    #[error("job failed: {0}")]
    JobFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

impl From<anyhow::Error> for CoreError {
    fn from(e: anyhow::Error) -> Self {
        CoreError::Other(e.to_string())
    }
}
