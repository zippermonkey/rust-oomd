use crate::plugins::interface::*;
use crate::plugins::base::*;
use crate::cgroup::types::*;
use crate::util::error::OomdError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Memory pressure detector plugin
pub struct MemoryPressureDetector {
    base: BasePlugin,
    threshold: f32,
    duration_seconds: u64,
    cgroup_pattern: String,
    pressure_history: std::collections::HashMap<String, Vec<(std::time::SystemTime, f32)>>,
}

impl MemoryPressureDetector {
    /// Create a new memory pressure detector
    pub fn new() -> Self {
        Self {
            base: BasePlugin::new(
                "memory_pressure_detector",
                "1.0.0",
                "Detects when memory pressure exceeds threshold",
            ),
            threshold: 80.0,
            duration_seconds: 30,
            cgroup_pattern: "*".to_string(),
            pressure_history: HashMap::new(),
        }
    }
    
    /// Configure the detector
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold;
        self
    }
    
    pub fn with_duration(mut self, duration_seconds: u64) -> Self {
        self.duration_seconds = duration_seconds;
        self
    }
    
    pub fn with_cgroup_pattern(mut self, pattern: String) -> Self {
        self.cgroup_pattern = pattern;
        self
    }
    
    /// Check if memory pressure threshold is exceeded
    async fn check_pressure_threshold(
        &self,
        context: &OomdContext,
        cgroup_path: &str,
    ) -> Result<bool, OomdError> {
        let cgroup_context = context.get_cgroup(cgroup_path)
            .ok_or_else(|| OomdError::CgroupNotFound(cgroup_path.to_string()))?;
        
        let pressure = cgroup_context.memory_pressure
            .as_ref()
            .ok_or_else(|| OomdError::PressureUnavailable(format!("No memory pressure data for {}", cgroup_path)))?;
        
        // Use weighted pressure for more accurate assessment
        let weighted_pressure = pressure.weighted();
        
        // Record pressure history
        let now = std::time::SystemTime::now();
        let mut history = self.pressure_history.get(cgroup_path).cloned().unwrap_or_default();
        history.push((now, weighted_pressure));
        
        // Keep only recent history
        history.retain(|(time, _)| {
            now.duration_since(*time).unwrap_or_default().as_secs() <= self.duration_seconds * 2
        });
        
        // Check if threshold has been exceeded for the required duration
        let threshold_exceeded_start = history.iter()
            .filter(|(_, pressure)| *pressure >= self.threshold)
            .map(|(time, _)| *time)
            .min();
        
        if let Some(start_time) = threshold_exceeded_start {
            let duration = now.duration_since(start_time).unwrap_or_default();
            Ok(duration.as_secs() >= self.duration_seconds)
        } else {
            Ok(false)
        }
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
impl Plugin for MemoryPressureDetector {
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
        if let Ok(threshold) = self.base.get_config::<f32>("threshold") {
            self.threshold = threshold;
        }
        
        if let Ok(duration) = self.base.get_config::<u64>("duration_seconds") {
            self.duration_seconds = duration;
        }
        
        if let Ok(pattern) = self.base.get_config::<String>("cgroup_pattern") {
            self.cgroup_pattern = pattern;
        }
        
        // Validate configuration
        if self.threshold <= 0.0 || self.threshold > 100.0 {
            return Err(OomdError::Config("Threshold must be between 0.0 and 100.0".to_string()));
        }
        
        if self.duration_seconds == 0 {
            return Err(OomdError::Config("Duration must be at least 1 second".to_string()));
        }
        
        self.base.update_status("threshold".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(self.threshold as f64).unwrap()));
        self.base.update_status("duration_seconds".to_string(), serde_json::Value::Number(serde_json::Number::from(self.duration_seconds)));
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
            match self.check_pressure_threshold(context, &cgroup_path).await {
                Ok(true) => {
                    triggered_cgroups.push(cgroup_path);
                },
                Ok(false) => {
                    // Threshold not exceeded
                },
                Err(e) => {
                    eprintln!("Error checking pressure for {}: {}", cgroup_path, e);
                }
            }
        }
        
        if !triggered_cgroups.is_empty() {
            let message = format!(
                "Memory pressure threshold {}% exceeded for {} cgroup(s): {:?}",
                self.threshold,
                triggered_cgroups.len(),
                triggered_cgroups
            );
            
            self.base.update_status("triggered".to_string(), serde_json::Value::Bool(true));
            self.base.update_status("triggered_cgroups".to_string(), serde_json::Value::Array(
                triggered_cgroups.iter().map(|c| serde_json::Value::String(c.clone())).collect()
            ));
            
            println!("Memory pressure detector: {}", message);
            
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
        status.insert("detector_type".to_string(), serde_json::Value::String("memory_pressure".to_string()));
        status
    }
}

#[async_trait]
impl DetectorPlugin for MemoryPressureDetector {
    async fn detect(&self, context: &OomdContext) -> Result<bool, OomdError> {
        let result = self.run(context).await?;
        Ok(matches!(result, PluginRet::Stop))
    }
    
    fn get_criteria(&self) -> DetectorCriteria {
        DetectorCriteria::MemoryPressure {
            threshold: self.threshold,
            duration_seconds: self.duration_seconds,
            cgroup_pattern: self.cgroup_pattern.clone(),
        }
    }
}

impl AsAny for MemoryPressureDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl PluginWithContext for MemoryPressureDetector {
    fn is_enabled(&self) -> bool {
        self.base.is_enabled()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryPressureDetectorConfig {
    pub threshold: f32,
    pub duration_seconds: u64,
    pub cgroup_pattern: String,
    pub enabled: bool,
}

impl Default for MemoryPressureDetectorConfig {
    fn default() -> Self {
        Self {
            threshold: 80.0,
            duration_seconds: 30,
            cgroup_pattern: "*".to_string(),
            enabled: true,
        }
    }
}