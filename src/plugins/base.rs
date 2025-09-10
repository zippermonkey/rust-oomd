use crate::plugins::interface::*;
use crate::util::error::OomdError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base plugin implementation that provides common functionality
pub struct BasePlugin {
    name: String,
    version: String,
    description: String,
    config: serde_json::Value,
    status: HashMap<String, serde_json::Value>,
    enabled: bool,
    error_count: u64,
    success_count: u64,
    last_run: Option<std::time::SystemTime>,
}

impl BasePlugin {
    /// Create a new base plugin
    pub fn new(name: &str, version: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            description: description.to_string(),
            config: serde_json::Value::Object(serde_json::Map::new()),
            status: HashMap::new(),
            enabled: true,
            error_count: 0,
            success_count: 0,
            last_run: None,
        }
    }
    
    /// Get plugin statistics
    pub fn get_stats(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();
        
        stats.insert("enabled".to_string(), serde_json::Value::Bool(self.enabled));
        stats.insert("error_count".to_string(), serde_json::Value::Number(serde_json::Number::from(self.error_count)));
        stats.insert("success_count".to_string(), serde_json::Value::Number(serde_json::Number::from(self.success_count)));
        
        if let Some(last_run) = self.last_run {
            stats.insert("last_run".to_string(), serde_json::Value::String(format!("{:?}", last_run)));
        }
        
        stats
    }
    
    /// Enable the plugin
    pub fn enable(&mut self) {
        self.enabled = true;
    }
    
    /// Disable the plugin
    pub fn disable(&mut self) {
        self.enabled = false;
    }
    
    /// Check if plugin is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    
    /// Record a successful run
    pub fn record_success(&mut self) {
        self.success_count += 1;
        self.last_run = Some(std::time::SystemTime::now());
    }
    
    /// Record an error
    pub fn record_error(&mut self) {
        self.error_count += 1;
    }
    
    /// Update status
    pub fn update_status(&mut self, key: String, value: serde_json::Value) {
        self.status.insert(key, value);
    }
    
    /// Get configuration value
    pub fn get_config<T>(&self, key: &str) -> Result<T, OomdError>
    where
        T: for<'de> Deserialize<'de>,
    {
        serde_json::from_value(self.config.get(key).cloned().unwrap_or_default())
            .map_err(|e| OomdError::Config(format!("Failed to parse config '{}': {}", key, e)))
    }
    
    /// Check if plugin has configuration
    pub fn has_config(&self, key: &str) -> bool {
        self.config.get(key).is_some()
    }
}

#[async_trait]
impl Plugin for BasePlugin {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn version(&self) -> &str {
        &self.version
    }
    
    fn description(&self) -> &str {
        &self.description
    }
    
    async fn init(&mut self, config: &serde_json::Value) -> Result<(), OomdError> {
        self.config = config.clone();
        self.update_status("initialized".to_string(), serde_json::Value::Bool(true));
        Ok(())
    }
    
    async fn run(&self, _context: &crate::cgroup::types::OomdContext) -> Result<PluginRet, OomdError> {
        // Base implementation does nothing
        Ok(PluginRet::Continue)
    }
    
    async fn cleanup(&self) -> Result<(), OomdError> {
        self.update_status("cleanup_complete".to_string(), serde_json::Value::Bool(true));
        Ok(())
    }
    
    fn get_status(&self) -> HashMap<String, serde_json::Value> {
        let mut status = self.status.clone();
        status.extend(self.get_stats());
        status
    }
}

/// Configuration helper for plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfigHelper {
    pub enabled: bool,
    pub priority: i32,
    pub timeout_seconds: u64,
    pub retry_count: u32,
    pub retry_delay_seconds: u64,
    pub log_level: String,
}

impl Default for PluginConfigHelper {
    fn default() -> Self {
        Self {
            enabled: true,
            priority: 0,
            timeout_seconds: 30,
            retry_count: 3,
            retry_delay_seconds: 1,
            log_level: "info".to_string(),
        }
    }
}

impl PluginConfigHelper {
    /// Create from JSON config
    pub fn from_config(config: &serde_json::Value) -> Result<Self, OomdError> {
        serde_json::from_value(config.clone())
            .map_err(|e| OomdError::Config(format!("Failed to parse plugin config: {}", e)))
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<(), OomdError> {
        if self.retry_count == 0 {
            return Err(OomdError::Config("Retry count must be at least 1".to_string()));
        }
        
        if self.timeout_seconds == 0 {
            return Err(OomdError::Config("Timeout must be at least 1 second".to_string()));
        }
        
        Ok(())
    }
}

/// Plugin execution context
#[derive(Debug, Clone)]
pub struct PluginExecutionContext {
    pub plugin_name: String,
    pub plugin_type: PluginType,
    pub config: serde_json::Value,
    pub dry_run: bool,
    pub verbose_logging: bool,
}

impl PluginExecutionContext {
    pub fn new(name: String, plugin_type: PluginType, config: serde_json::Value) -> Self {
        Self {
            plugin_name: name,
            plugin_type,
            config,
            dry_run: false,
            verbose_logging: false,
        }
    }
    
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }
    
    pub fn with_verbose_logging(mut self, verbose: bool) -> Self {
        self.verbose_logging = verbose;
        self
    }
}

/// Plugin execution result with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginExecutionResult {
    pub plugin_name: String,
    pub plugin_type: PluginType,
    pub result: PluginRet,
    pub execution_time_ms: u64,
    pub message: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl PluginExecutionResult {
    pub fn new(name: String, plugin_type: PluginType, result: PluginRet) -> Self {
        Self {
            plugin_name: name,
            plugin_type,
            result,
            execution_time_ms: 0,
            message: None,
            metadata: HashMap::new(),
        }
    }
    
    pub fn with_execution_time(mut self, time_ms: u64) -> Self {
        self.execution_time_ms = time_ms;
        self
    }
    
    pub fn with_message(mut self, message: String) -> Self {
        self.message = Some(message);
        self
    }
    
    pub fn with_metadata(mut self, metadata: HashMap<String, serde_json::Value>) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Plugin trait extension for execution context
#[async_trait]
pub trait PluginWithContext: Plugin {
    /// Execute plugin with context
    async fn run_with_context(
        &self,
        context: &crate::cgroup::types::OomdContext,
        exec_context: &PluginExecutionContext,
    ) -> Result<PluginExecutionResult, OomdError> {
        let start_time = std::time::Instant::now();
        
        if !self.is_enabled() {
            return Ok(PluginExecutionResult::new(
                self.name().to_string(),
                exec_context.plugin_type.clone(),
                PluginRet::Continue,
            )
            .with_execution_time(0)
            .with_message("Plugin disabled".to_string()));
        }
        
        let result = if exec_context.dry_run {
            Ok(PluginRet::Continue)
        } else {
            self.run(context).await
        };
        
        let execution_time = start_time.elapsed().as_millis() as u64;
        
        match result {
            Ok(plugin_ret) => {
                let mut exec_result = PluginExecutionResult::new(
                    self.name().to_string(),
                    exec_context.plugin_type.clone(),
                    plugin_ret,
                )
                .with_execution_time(execution_time);
                
                if let Some(msg) = &exec_result.message {
                    exec_result.metadata.insert("message".to_string(), serde_json::Value::String(msg.clone()));
                }
                
                Ok(exec_result)
            },
            Err(e) => {
                let exec_result = PluginExecutionResult::new(
                    self.name().to_string(),
                    exec_context.plugin_type.clone(),
                    PluginRet::Continue, // Continue on error by default
                )
                .with_execution_time(execution_time)
                .with_message(format!("Plugin execution failed: {}", e));
                
                Ok(exec_result)
            }
        }
    }
    
    /// Check if plugin is enabled
    fn is_enabled(&self) -> bool;
}

impl PluginWithContext for BasePlugin {
    fn is_enabled(&self) -> bool {
        self.enabled
    }
}