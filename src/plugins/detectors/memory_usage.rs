use crate::plugins::interface::*;
use crate::plugins::base::*;
use crate::cgroup::types::*;
use crate::util::error::OomdError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Memory usage detector plugin
pub struct MemoryUsageDetector {
    base: BasePlugin,
    threshold_bytes: u64,
    threshold_percentage: Option<f32>,
    cgroup_pattern: String,
}

impl MemoryUsageDetector {
    /// Create a new memory usage detector
    pub fn new() -> Self {
        Self {
            base: BasePlugin::new(
                "memory_usage_detector",
                "1.0.0",
                "Detects when memory usage exceeds threshold",
            ),
            threshold_bytes: 1024 * 1024 * 1024, // 1GB default
            threshold_percentage: None,
            cgroup_pattern: "*".to_string(),
        }
    }
    
    /// Configure the detector
    pub fn with_threshold_bytes(mut self, threshold_bytes: u64) -> Self {
        self.threshold_bytes = threshold_bytes;
        self
    }
    
    pub fn with_threshold_percentage(mut self, threshold_percentage: f32) -> Self {
        self.threshold_percentage = Some(threshold_percentage);
        self
    }
    
    pub fn with_cgroup_pattern(mut self, pattern: String) -> Self {
        self.cgroup_pattern = pattern;
        self
    }
    
    /// Check if memory usage threshold is exceeded
    async fn check_usage_threshold(
        &self,
        context: &OomdContext,
        cgroup_path: &str,
    ) -> Result<bool, OomdError> {
        let cgroup_context = context.get_cgroup(cgroup_path)
            .ok_or_else(|| OomdError::CgroupNotFound(cgroup_path.to_string()))?;
        
        let usage = cgroup_context.memory_usage
            .ok_or_else(|| OomdError::PressureUnavailable(format!("No memory usage data for {}", cgroup_path)))?;
        
        // Check absolute threshold
        let absolute_exceeded = usage >= self.threshold_bytes;
        
        // Check percentage threshold if configured
        let percentage_exceeded = if let Some(percentage) = self.threshold_percentage {
            if let Some(limit) = cgroup_context.memory_limit {
                if limit == 0 {
                    false
                } else {
                    let usage_percentage = (usage as f64 / limit as f64) * 100.0;
                    usage_percentage >= percentage as f64
                }
            } else {
                false
            }
        } else {
            false
        };
        
        Ok(absolute_exceeded || percentage_exceeded)
    }
    
    /// Find cgroups matching the pattern
    fn find_matching_cgroups(&self, context: &OomdContext) -> Vec<String> {
        context.cgroups.keys()
            .filter(|path| {
                if self.cgroup_pattern == "*" {
                    true
                } else {
                    path.contains(&self.cgroup_pattern)
                }
            })
            .cloned()
            .collect()
    }
}

#[async_trait]
impl Plugin for MemoryUsageDetector {
    fn name(&self) -> &str {
        self.base.name()
    }
    
    fn version(&self) -> &str {
        self.base.version()
    }
    
    fn description(&self) -> &str {
        self.base.description()
    }
    
    async fn init(&mut self, config: &serde_json::Value) -> Result<(), OomdError> {
        self.base.init(config).await?;
        
        // Parse configuration
        if let Ok(threshold_bytes) = self.base.get_config::<u64>("threshold_bytes") {
            self.threshold_bytes = threshold_bytes;
        }
        
        if let Ok(threshold_percentage) = self.base.get_config::<f32>("threshold_percentage") {
            self.threshold_percentage = Some(threshold_percentage);
        }
        
        if let Ok(pattern) = self.base.get_config::<String>("cgroup_pattern") {
            self.cgroup_pattern = pattern;
        }
        
        // Validate configuration
        if self.threshold_bytes == 0 {
            return Err(OomdError::Config("Threshold bytes must be greater than 0".to_string()));
        }
        
        if let Some(percentage) = self.threshold_percentage {
            if percentage <= 0.0 || percentage > 100.0 {
                return Err(OomdError::Config("Threshold percentage must be between 0.0 and 100.0".to_string()));
            }
        }
        
        self.base.update_status("threshold_bytes".to_string(), serde_json::Value::Number(serde_json::Number::from(self.threshold_bytes)));
        self.base.update_status("threshold_percentage".to_string(), 
            self.threshold_percentage.map(|p| serde_json::Value::Number(serde_json::Number::from_f64(p as f64).unwrap()))
                .unwrap_or(serde_json::Value::Null));
        self.base.update_status("cgroup_pattern".to_string(), serde_json::Value::String(self.cgroup_pattern.clone()));
        
        Ok(())
    }
    
    async fn run(&self, context: &OomdContext) -> Result<PluginRet, OomdError> {
        if !self.base.is_enabled() {
            return Ok(PluginRet::Continue);
        }
        
        let matching_cgroups = self.find_matching_cgroups(context);
        let mut triggered_cgroups = Vec::new();
        
        for cgroup_path in matching_cgroups {
            match self.check_usage_threshold(context, &cgroup_path).await {
                Ok(true) => {
                    triggered_cgroups.push(cgroup_path);
                },
                Ok(false) => {
                    // Threshold not exceeded
                },
                Err(e) => {
                    eprintln!("Error checking usage for {}: {}", cgroup_path, e);
                }
            }
        }
        
        if !triggered_cgroups.is_empty() {
            let message = format!(
                "Memory usage threshold exceeded for {} cgroup(s): {:?}",
                triggered_cgroups.len(),
                triggered_cgroups
            );
            
            self.base.update_status("triggered".to_string(), serde_json::Value::Bool(true));
            self.base.update_status("triggered_cgroups".to_string(), serde_json::Value::Array(
                triggered_cgroups.iter().map(|c| serde_json::Value::String(c.clone())).collect()
            ));
            
            println!("Memory usage detector: {}", message);
            
            return Ok(PluginRet::Stop);
        }
        
        self.base.update_status("triggered".to_string(), serde_json::Value::Bool(false));
        Ok(PluginRet::Continue)
    }
    
    async fn cleanup(&self) -> Result<(), OomdError> {
        self.base.cleanup().await
    }
    
    fn get_status(&self) -> HashMap<String, serde_json::Value> {
        let mut status = self.base.get_status();
        status.insert("type".to_string(), serde_json::Value::String("detector".to_string()));
        status.insert("detector_type".to_string(), serde_json::Value::String("memory_usage".to_string()));
        status
    }
}

#[async_trait]
impl DetectorPlugin for MemoryUsageDetector {
    async fn detect(&self, context: &OomdContext) -> Result<bool, OomdError> {
        let result = self.run(context).await?;
        Ok(matches!(result, PluginRet::Stop))
    }
    
    fn get_criteria(&self) -> DetectorCriteria {
        DetectorCriteria::MemoryUsage {
            threshold_bytes: self.threshold_bytes,
            percentage: self.threshold_percentage,
            cgroup_pattern: self.cgroup_pattern.clone(),
        }
    }
}

impl AsAny for MemoryUsageDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl PluginWithContext for MemoryUsageDetector {
    fn is_enabled(&self) -> bool {
        self.base.is_enabled()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryUsageDetectorConfig {
    pub threshold_bytes: u64,
    pub threshold_percentage: Option<f32>,
    pub cgroup_pattern: String,
    pub enabled: bool,
}

impl Default for MemoryUsageDetectorConfig {
    fn default() -> Self {
        Self {
            threshold_bytes: 1024 * 1024 * 1024, // 1GB
            threshold_percentage: None,
            cgroup_pattern: "*".to_string(),
            enabled: true,
        }
    }
}