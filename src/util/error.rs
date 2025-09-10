use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OomdError {
    #[error("Cgroup not found: {0}")]
    CgroupNotFound(String),
    
    #[error("Invalid cgroup path: {0}")]
    InvalidPath(PathBuf),
    
    #[error("Unsupported cgroup version: {0:?}")]
    UnsupportedVersion(super::cgroup::types::CgroupVersion),
    
    #[error("Pressure data unavailable for {0}")]
    PressureUnavailable(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Parse error: {0}")]
    Parse(String),
    
    #[error("Nix error: {0}")]
    Nix(#[from] nix::Error),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Plugin error: {0}")]
    Plugin(String),
    
    #[error("Config error: {0}")]
    Config(String),
    
    #[error("System error: {0}")]
    System(String),
}

pub type Result<T> = std::result::Result<T, OomdError>;