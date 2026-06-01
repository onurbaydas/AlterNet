use thiserror::Error;

#[derive(Error, Debug)]
pub enum AlterNetError {
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Block store error: {0}")]
    BlockStore(String),

    #[error("WASM execution error: {0}")]
    Wasm(String),

    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, AlterNetError>;
