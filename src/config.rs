use core::{error::Error, fmt};
use std::{fs, io, path::PathBuf};

use jsonwebtoken::Algorithm;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub api_key: String,
    pub jwk_path: PathBuf,
    pub jwk_kid: String,
    pub jwk_algorithm: Algorithm,
    pub database_url: String,
    pub allowed_api_keys: Vec<String>,
    pub api_key_header: String,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            api_key: "identity-service".to_string(),
            jwk_path: PathBuf::from("path/to/key.pem"),
            jwk_kid: "some-id-for-the-key".to_string(),
            jwk_algorithm: Algorithm::ES256,
            database_url: "postgres://user:password@localhost:5423".to_string(),
            allowed_api_keys: vec!["identity-service".to_string()],
            api_key_header: "X-TS-API-Key".to_string(),
        }
    }
}

impl Config {
    pub fn read() -> Result<Self, ConfigReadError> {
        let file = fs::read_to_string("config.json").map_err(|source| ConfigReadError {
            kind: ConfigReadErrorKind::IoRead { source },
        })?;

        let config = serde_json::from_str(&file).map_err(|source| ConfigReadError {
            kind: ConfigReadErrorKind::Deserialize { source },
        })?;

        Ok(config)
    }

    pub fn write_default() -> Result<(), ConfigWriteError> {
        let contents =
            serde_json::to_string_pretty(&Self::default()).map_err(|source| ConfigWriteError {
                kind: ConfigWriteErrorKind::Serialize { source },
            })?;

        fs::write("config.json", contents).map_err(|source| ConfigWriteError {
            kind: ConfigWriteErrorKind::IoWrite { source },
        })
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct ConfigWriteError {
    pub kind: ConfigWriteErrorKind,
}
impl fmt::Display for ConfigWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to write config file")
    }
}
impl Error for ConfigWriteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.kind)
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum ConfigWriteErrorKind {
    #[non_exhaustive]
    IoWrite { source: io::Error },

    #[non_exhaustive]
    Serialize { source: serde_json::Error },
}
impl fmt::Display for ConfigWriteErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            ConfigWriteErrorKind::IoWrite { .. } => write!(f, "io error when writing"),
            ConfigWriteErrorKind::Serialize { .. } => write!(f, "serializing failed"),
        }
    }
}
impl Error for ConfigWriteErrorKind {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            ConfigWriteErrorKind::IoWrite { source } => Some(source),
            ConfigWriteErrorKind::Serialize { source } => Some(source),
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct ConfigReadError {
    pub kind: ConfigReadErrorKind,
}
impl fmt::Display for ConfigReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to read config file")
    }
}
impl Error for ConfigReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.kind)
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum ConfigReadErrorKind {
    #[non_exhaustive]
    IoRead { source: io::Error },

    #[non_exhaustive]
    Deserialize { source: serde_json::Error },
}
impl fmt::Display for ConfigReadErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            ConfigReadErrorKind::IoRead { .. } => write!(f, "io error when reading"),
            ConfigReadErrorKind::Deserialize { .. } => write!(f, "deserializing failed"),
        }
    }
}
impl Error for ConfigReadErrorKind {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            ConfigReadErrorKind::IoRead { source } => Some(source),
            ConfigReadErrorKind::Deserialize { source } => Some(source),
        }
    }
}
