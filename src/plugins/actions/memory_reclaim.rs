use crate::plugins::interface::*;
use crate::plugins::base::*;
use crate::cgroup::types::*;
use crate::cgroup::manager::CgroupManager;
use crate::util::error::OomdError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Memory reclaim action plugin - attempts to reclaim memory from cgroups
pub struct MemoryReclaimAction {
    base: BasePlugin,
    reclaim_strategy: ReclaimStrategy,
    reclaim_amount_bytes: u64,
    dry_run: bool,
    cgroup_manager: Option<Arc<CgroupManager>>,
}

/// Reclaim strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReclaimStrategy {
    /// Drop page cache
    DropCache,
    /// Reclaim from specific cgroup
    CgroupTarget { cgroup_path: String, percentage: f32 },
    /// Reclaim from all cgroups
    AllCgroups { percentage: f32 },
    /// Reclaim from cgroups with highest memory usage
    HighestUsage { percentage: f32, cgroup_count: usize },
}

impl Default for ReclaimStrategy {
    fn default() -> Self {
        ReclaimStrategy::DropCache
    }
}

impl MemoryReclaimAction {
    /// Create a new memory reclaim action
    pub fn new() -> Self {
        Self {
            base: BasePlugin::new(
                "memory_reclaim_action",
                "1.0.0",
                "Reclaims memory from cgroups using various strategies",
            ),
            reclaim_strategy: ReclaimStrategy::default(),
            reclaim_amount_bytes: 100 * 1024 * 1024, // 100MB default
            dry_run: false,
            cgroup_manager: None,
        }
    }
    
    /// Configure the reclaim action
    pub fn with_strategy(mut self, strategy: ReclaimStrategy) -> Self {
        self.reclaim_strategy = strategy;
        self
    }
    
    pub fn with_reclaim_amount(mut self, amount_bytes: u64) -> Self {
        self.reclaim_amount_bytes = amount_bytes;
        self
    }
    
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }
    
    pub fn with_cgroup_manager(mut self, manager: Arc<CgroupManager>) -> Self {
        self.cgroup_manager = Some(manager);
        self
    }
    
    /// Drop page cache system-wide
    async fn drop_page_cache(&self) -> Result<ActionResult, OomdError> {
        if self.dry_run {
            return Ok(ActionResult::Skipped {
                reason: "Dry run: would drop page cache".to_string(),
            });
        }
        
        // Write to /proc/sys/vm/drop_caches
        // This requires root privileges
        let drop_caches_path = "/proc/sys/vm/drop_caches";
        
        // Read current value first
        let current_value = std::fs::read_to_string(drop_caches_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "0".to_string());
        
        // Write 1 to drop page cache
        std::fs::write(drop_caches_path, "1")
            .map_err(|e| OomdError::Io(e))?;
        
        // Restore original value after a short delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        std::fs::write(drop_caches_path, &current_value)
            .map_err(|e| OomdError::Io(e))?;
        
        let mut details = HashMap::new();
        details.insert("action".to_string(), serde_json::Value::String("drop_page_cache".to_string()));
        details.insert("previous_value".to_string(), serde_json::Value::String(current_value));
        
        Ok(ActionResult::Success {
            message: "Page cache dropped successfully".to_string(),
            details,
        })
    }
    
    /// Reclaim memory from a specific cgroup
    async fn reclaim_from_cgroup(&self, cgroup_path: &str, amount: u64) -> Result<ActionResult, OomdError> {
        if let Some(manager) = &self.cgroup_manager {
            let cgroup_path_obj = manager.create_cgroup_path(std::path::PathBuf::from(cgroup_path))?;
            
            if self.dry_run {
                let mut details = HashMap::new();
                details.insert("cgroup".to_string(), serde_json::Value::String(cgroup_path.to_string()));
                details.insert("amount".to_string(), serde_json::Value::Number(serde_json::Number::from(amount)));
                
                return Ok(ActionResult::Skipped {
                    reason: format!("Dry run: would reclaim {} bytes from {}", amount, cgroup_path),
                });
            }
            
            // Attempt to reclaim memory
            match manager.memory_reclaim(&cgroup_path_obj, amount).await {
                Ok(_) => {
                    let mut details = HashMap::new();
                    details.insert("cgroup".to_string(), serde_json::Value::String(cgroup_path.to_string()));
                    details.insert("amount".to_string(), serde_json::Value::Number(serde_json::Number::from(amount)));
                    
                    Ok(ActionResult::Success {
                        message: format!("Reclaimed {} bytes from {}", amount, cgroup_path),
                        details,
                    })
                },
                Err(e) => {
                    let mut details = HashMap::new();
                    details.insert("cgroup".to_string(), serde_json::Value::String(cgroup_path.to_string()));
                    details.insert("amount".to_string(), serde_json::Value::Number(serde_json::Number::from(amount)));
                    details.insert("error".to_string(), serde_json::Value::String(e.to_string()));
                    
                    Ok(ActionResult::Failed {
                        error: format!("Failed to reclaim from {}: {}", cgroup_path, e),
                        details,
                    })
                }
            }
        } else {
            Ok(ActionResult::Failed {
                error: "Cgroup manager not available".to_string(),
                details: HashMap::new(),
            })
        }
    }
    
    /// Reclaim memory from multiple cgroups
    async fn reclaim_from_multiple_cgroups(
        &self,
        context: &OomdContext,
        cgroups: Vec<String>,
        amount_per_cgroup: u64,
    ) -> Result<ActionResult, OomdError> {
        let mut results = Vec::new();
        let mut total_reclaimed = 0;
        
        for cgroup_path in cgroups {
            match self.reclaim_from_cgroup(&cgroup_path, amount_per_cgroup).await {
                Ok(ActionResult::Success { message, .. }) => {
                    results.push(message);
                    total_reclaimed += amount_per_cgroup;
                },
                Ok(ActionResult::Failed { error, .. }) => {
                    results.push(error);
                },
                Ok(ActionResult::Skipped { reason }) => {
                    results.push(reason);
                },
                Err(e) => {
                    results.push(format!("Error reclaiming from {}: {}", cgroup_path, e));
                }
            }
        }
        
        let mut details = HashMap::new();
        details.insert("cgroups_attempted".to_string(), serde_json::Value::Number(serde_json::Number::from(cgroups.len())));
        details.insert("total_reclaimed".to_string(), serde_json::Value::Number(serde_json::Number::from(total_reclaimed)));
        details.insert("results".to_string(), serde_json::Value::Array(
            results.iter().map(|r| serde_json::Value::String(r.clone())).collect()
        ));
        
        if total_reclaimed > 0 {
            Ok(ActionResult::Success {
                message: format!("Reclaimed {} bytes from {} cgroups", total_reclaimed, cgroups.len()),
                details,
            })
        } else {
            Ok(ActionResult::Failed {
                error: "No memory reclaimed".to_string(),
                details,
            })
        }
    }
    
    /// Find cgroups with highest memory usage
    fn find_highest_usage_cgroups(&self, context: &OomdContext, count: usize) -> Vec<String> {
        let mut cgroups: Vec<(String, u64)> = context.cgroups.iter()
            .filter_map(|(path, cgroup)| {
                cgroup.memory_usage.map(|usage| (path.clone(), usage))
            })
            .collect();
        
        // Sort by memory usage (highest first)
        cgroups.sort_by(|a, b| b.1.cmp(&a.1));
        
        // Take top N cgroups
        cgroups.truncate(count);
        cgroups.into_iter().map(|(path, _)| path).collect()
    }
}

#[async_trait]
impl Plugin for MemoryReclaimAction {
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
        if let Ok(strategy) = self.base.get_config::<String>("strategy") {
            self.reclaim_strategy = match strategy.as_str() {
                "drop_cache" => ReclaimStrategy::DropCache,
                "cgroup_target" => {
                    let cgroup_path = self.base.get_config::<String>("cgroup_path").unwrap_or_default();
                    let percentage = self.base.get_config::<f32>("percentage").unwrap_or(10.0);
                    ReclaimStrategy::CgroupTarget { cgroup_path, percentage }
                },
                "all_cgroups" => {
                    let percentage = self.base.get_config::<f32>("percentage").unwrap_or(10.0);
                    ReclaimStrategy::AllCgroups { percentage }
                },
                "highest_usage" => {
                    let percentage = self.base.get_config::<f32>("percentage").unwrap_or(10.0);
                    let cgroup_count = self.base.get_config::<usize>("cgroup_count").unwrap_or(3);
                    ReclaimStrategy::HighestUsage { percentage, cgroup_count }
                },
                _ => ReclaimStrategy::default(),
            };
        }
        
        if let Ok(amount) = self.base.get_config::<u64>("reclaim_amount_bytes") {
            self.reclaim_amount_bytes = amount;
        }
        
        if let Ok(dry_run) = self.base.get_config::<bool>("dry_run") {
            self.dry_run = dry_run;
        }
        
        // Validate configuration
        if self.reclaim_amount_bytes == 0 {
            return Err(OomdError::Config("Reclaim amount must be greater than 0".to_string()));
        }
        
        self.base.update_status("strategy".to_string(), serde_json::Value::String(format!("{:?}", self.reclaim_strategy)));
        self.base.update_status("reclaim_amount_bytes".to_string(), serde_json::Value::Number(serde_json::Number::from(self.reclaim_amount_bytes)));
        self.base.update_status("dry_run".to_string(), serde_json::Value::Bool(self.dry_run));
        
        Ok(())
    }
    
    async fn run(&self, context: &OomdContext) -> Result<PluginRet, OomdError> {
        if !self.base.is_enabled() {
            return Ok(PluginRet::Continue);
        }
        
        let result = match &self.reclaim_strategy {
            ReclaimStrategy::DropCache => {
                self.drop_page_cache().await
            },
            ReclaimStrategy::CgroupTarget { cgroup_path, percentage } => {
                let amount = (self.reclaim_amount_bytes as f64 * (*percentage as f64 / 100.0)) as u64;
                self.reclaim_from_cgroup(cgroup_path, amount).await
            },
            ReclaimStrategy::AllCgroups { percentage } => {
                let cgroups: Vec<String> = context.cgroups.keys().cloned().collect();
                let amount_per_cgroup = (self.reclaim_amount_bytes as f64 * (*percentage as f64 / 100.0)) as u64;
                self.reclaim_from_multiple_cgroups(context, cgroups, amount_per_cgroup).await
            },
            ReclaimStrategy::HighestUsage { percentage, cgroup_count } => {
                let cgroups = self.find_highest_usage_cgroups(context, *cgroup_count);
                let amount_per_cgroup = (self.reclaim_amount_bytes as f64 * (*percentage as f64 / 100.0)) as u64;
                self.reclaim_from_multiple_cgroups(context, cgroups, amount_per_cgroup).await
            },
        };
        
        match result {
            Ok(ActionResult::Success { message, mut details }) => {
                details.insert("strategy".to_string(), serde_json::Value::String(format!("{:?}", self.reclaim_strategy)));
                self.base.update_status("last_result".to_string(), serde_json::Value::String("success".to_string()));
                self.base.update_status("last_message".to_string(), serde_json::Value::String(message.clone()));
                println!("Memory reclaim action: {}", message);
            },
            Ok(ActionResult::Failed { error, .. }) => {
                self.base.update_status("last_result".to_string(), serde_json::Value::String("failed".to_string()));
                self.base.update_status("last_error".to_string(), serde_json::Value::String(error.clone()));
                eprintln!("Memory reclaim action failed: {}", error);
            },
            Ok(ActionResult::Skipped { reason }) => {
                self.base.update_status("last_result".to_string(), serde_json::Value::String("skipped".to_string()));
                self.base.update_status("last_skip_reason".to_string(), serde_json::Value::String(reason.clone()));
                println!("Memory reclaim action skipped: {}", reason);
            },
            Err(e) => {
                self.base.update_status("last_result".to_string(), serde_json::Value::String("error".to_string()));
                self.base.update_status("last_error".to_string(), serde_json::Value::String(e.to_string()));
                eprintln!("Memory reclaim action error: {}", e);
            }
        }
        
        Ok(PluginRet::Continue)
    }
    
    async fn cleanup(&self) -> Result<(), OomdError> {
        self.base.cleanup().await
    }
    
    fn get_status(&self) -> HashMap<String, serde_json::Value> {
        let mut status = self.base.get_status();
        status.insert("type".to_string(), serde_json::Value::String("action".to_string()));
        status.insert("action_type".to_string(), serde_json::Value::String("memory_reclaim".to_string()));
        status
    }
}

#[async_trait]
impl ActionPlugin for MemoryReclaimAction {
    async fn execute(&self, context: &OomdContext, _target: Option<&CgroupContext>) -> Result<ActionResult, OomdError> {
        self.run(context).await?;
        Ok(ActionResult::Success {
            message: "Memory reclaim action executed".to_string(),
            details: HashMap::new(),
        })
    }
    
    async fn can_execute(&self, _context: &OomdContext) -> Result<bool, OomdError> {
        // Check if we have the required permissions
        // This is a simplified check - in reality, you'd want more comprehensive validation
        Ok(true)
    }
}

impl AsAny for MemoryReclaimAction {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl PluginWithContext for MemoryReclaimAction {
    fn is_enabled(&self) -> bool {
        self.base.is_enabled()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryReclaimActionConfig {
    pub strategy: String,
    pub reclaim_amount_bytes: u64,
    pub percentage: Option<f32>,
    pub cgroup_path: Option<String>,
    pub cgroup_count: Option<usize>,
    pub dry_run: bool,
    pub enabled: bool,
}

impl Default for MemoryReclaimActionConfig {
    fn default() -> Self {
        Self {
            strategy: "drop_cache".to_string(),
            reclaim_amount_bytes: 100 * 1024 * 1024, // 100MB
            percentage: Some(10.0),
            cgroup_path: None,
            cgroup_count: Some(3),
            dry_run: false,
            enabled: true,
        }
    }
}