use async_trait::async_trait;
use crate::cgroup::types::*;
use crate::core::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Plugin trait that all oomd plugins must implement
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Get the plugin name
    fn name(&self) -> &str;
    
    /// Get the plugin version
    fn version(&self) -> &str;
    
    /// Get plugin description
    fn description(&self) -> &str;
    
    /// Initialize the plugin with configuration
    async fn init(&mut self, config: &serde_json::Value) -> Result<(), crate::util::error::OomdError>;
    
    /// Run the plugin logic
    async fn run(&self, context: &OomdContext) -> Result<PluginRet, crate::util::error::OomdError>;
    
    /// Clean up plugin resources
    async fn cleanup(&self) -> Result<(), crate::util::error::OomdError>;
    
    /// Get plugin-specific metrics/status
    fn get_status(&self) -> HashMap<String, serde_json::Value>;
}

/// Detector plugin - monitors system conditions
#[async_trait]
pub trait DetectorPlugin: Plugin {
    /// Check if the detector conditions are met
    async fn detect(&self, context: &OomdContext) -> Result<bool, crate::util::error::OomdError>;
    
    /// Get the detection threshold or criteria
    fn get_criteria(&self) -> DetectorCriteria;
}

/// Action plugin - takes corrective actions
#[async_trait]
pub trait ActionPlugin: Plugin {
    /// Execute the action
    async fn execute(&self, context: &OomdContext, target: Option<&CgroupContext>) -> Result<ActionResult, crate::util::error::OomdError>;
    
    /// Check if the action can be safely executed
    async fn can_execute(&self, context: &OomdContext) -> Result<bool, crate::util::error::OomdError>;
}

/// Detector criteria configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectorCriteria {
    /// Memory pressure threshold
    MemoryPressure {
        threshold: f32,
        duration_seconds: u64,
        cgroup_pattern: String,
    },
    /// Memory usage threshold
    MemoryUsage {
        threshold_bytes: u64,
        percentage: Option<f32>,
        cgroup_pattern: String,
    },
    /// IO pressure threshold
    IOPressure {
        threshold: f32,
        duration_seconds: u64,
        cgroup_pattern: String,
    },
    /// Custom criteria
    Custom {
        criteria: HashMap<String, serde_json::Value>,
    },
}

/// Action execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionResult {
    /// Action completed successfully
    Success {
        message: String,
        details: HashMap<String, serde_json::Value>,
    },
    /// Action failed
    Failed {
        error: String,
        details: HashMap<String, serde_json::Value>,
    },
    /// Action skipped (conditions not met)
    Skipped {
        reason: String,
    },
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub name: String,
    pub plugin_type: PluginType,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub priority: i32,
    pub timeout_seconds: Option<u64>,
}

/// Plugin type classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginType {
    Detector,
    Action,
    Hybrid, // Both detector and action
}

/// Plugin metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub license: String,
    pub plugin_type: PluginType,
    pub dependencies: Vec<String>,
    pub capabilities: Vec<String>,
}