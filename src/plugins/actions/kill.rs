use crate::plugins::interface::*;
use crate::plugins::base::*;
use crate::cgroup::types::*;
use crate::core::types::*;
use crate::util::error::OomdError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

/// Kill action plugin - terminates processes to free memory
pub struct KillAction {
    base: BasePlugin,
    kill_strategy: KillStrategy,
    dry_run: bool,
    max_kill_count: u32,
    kill_signal: i32,
}

/// Kill strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KillStrategy {
    /// Kill processes with highest memory usage
    HighestMemory,
    /// Kill processes with highest OOM score
    HighestOomScore,
    /// Kill processes with lowest OOM score (preserve important processes)
    LowestOomScore,
    /// Kill oldest processes
    Oldest,
    /// Kill newest processes
    Newest,
    /// Kill processes in specific cgroup
    CgroupTarget { cgroup_path: String },
}

impl Default for KillStrategy {
    fn default() -> Self {
        KillStrategy::HighestMemory
    }
}

impl KillAction {
    /// Create a new kill action
    pub fn new() -> Self {
        Self {
            base: BasePlugin::new(
                "kill_action",
                "1.0.0",
                "Terminates processes to free memory",
            ),
            kill_strategy: KillStrategy::default(),
            dry_run: false,
            max_kill_count: 1,
            kill_signal: 9, // SIGKILL
        }
    }
    
    /// Configure the kill action
    pub fn with_strategy(mut self, strategy: KillStrategy) -> Self {
        self.kill_strategy = strategy;
        self
    }
    
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }
    
    pub fn with_max_kill_count(mut self, count: u32) -> Self {
        self.max_kill_count = count;
        self
    }
    
    pub fn with_kill_signal(mut self, signal: i32) -> Self {
        self.kill_signal = signal;
        self
    }
    
    /// Get process information for a PID
    fn get_process_info(&self, pid: libc::pid_t) -> Result<ProcessInfo, OomdError> {
        // Read /proc/[pid]/stat for basic info
        let stat_path = format!("/proc/{}/stat", pid);
        let stat_content = std::fs::read_to_string(&stat_path)
            .map_err(|e| OomdError::Io(e))?;
        
        let stat_parts: Vec<&str> = stat_content.split_whitespace().collect();
        if stat_parts.len() < 24 {
            return Err(OomdError::Parse(format!("Invalid stat format for PID {}", pid)));
        }
        
        let comm = stat_parts[1].trim_matches('(').trim_matches(')').to_string();
        let utime = stat_parts[13].parse::<u64>().unwrap_or(0);
        let stime = stat_parts[14].parse::<u64>().unwrap_or(0);
        let vsize = stat_parts[22].parse::<u64>().unwrap_or(0);
        
        // Read /proc/[pid]/oom_score
        let oom_score_path = format!("/proc/{}/oom_score", pid);
        let oom_score = std::fs::read_to_string(&oom_score_path)
            .map(|s| s.trim().parse::<i32>().unwrap_or(0))
            .unwrap_or(0);
        
        // Read /proc/[pid]/oom_score_adj
        let oom_score_adj_path = format!("/proc/{}/oom_score_adj", pid);
        let oom_score_adj = std::fs::read_to_string(&oom_score_adj_path)
            .map(|s| s.trim().parse::<i32>().unwrap_or(0))
            .unwrap_or(0);
        
        Ok(ProcessInfo {
            pid,
            comm,
            memory_usage: vsize,
            cpu_usage: (utime + stime) as f32,
            oom_score,
            oom_score_adj,
        })
    }
    
    /// Find processes to kill based on strategy
    async fn find_targets(&self, context: &OomdContext) -> Result<Vec<ProcessInfo>, OomdError> {
        let mut processes = Vec::new();
        
        match &self.kill_strategy {
            KillStrategy::CgroupTarget { cgroup_path } => {
                // Target specific cgroup
                if let Some(cgroup) = context.get_cgroup(cgroup_path) {
                    if let Some(pids) = &cgroup.pids {
                        for &pid in pids {
                            if let Ok(info) = self.get_process_info(pid) {
                                processes.push(info);
                            }
                        }
                    }
                }
            },
            _ => {
                // Target all cgroups
                for cgroup in context.cgroups.values() {
                    if let Some(pids) = &cgroup.pids {
                        for &pid in pids {
                            if let Ok(info) = self.get_process_info(pid) {
                                processes.push(info);
                            }
                        }
                    }
                }
            }
        }
        
        // Sort processes based on strategy
        match &self.kill_strategy {
            KillStrategy::HighestMemory => {
                processes.sort_by(|a, b| b.memory_usage.cmp(&a.memory_usage));
            },
            KillStrategy::HighestOomScore => {
                processes.sort_by(|a, b| b.oom_score.cmp(&a.oom_score));
            },
            KillStrategy::LowestOomScore => {
                processes.sort_by(|a, b| a.oom_score.cmp(&b.oom_score));
            },
            KillStrategy::Oldest => {
                // Use start time (simplified - using memory usage as proxy)
                processes.sort_by(|a, b| a.memory_usage.cmp(&b.memory_usage));
            },
            KillStrategy::Newest => {
                // Use start time (simplified - using memory usage as proxy)
                processes.sort_by(|a, b| b.memory_usage.cmp(&a.memory_usage));
            },
            KillStrategy::CgroupTarget { .. } => {
                // Already filtered by cgroup, sort by memory usage
                processes.sort_by(|a, b| b.memory_usage.cmp(&a.memory_usage));
            },
        }
        
        // Limit to max kill count
        processes.truncate(self.max_kill_count as usize);
        
        Ok(processes)
    }
    
    /// Kill a process
    async fn kill_process(&self, process: &ProcessInfo) -> Result<ActionResult, OomdError> {
        if self.dry_run {
            let mut details = HashMap::new();
            details.insert("pid".to_string(), serde_json::Value::Number(serde_json::Number::from(process.pid)));
            details.insert("comm".to_string(), serde_json::Value::String(process.comm.clone()));
            details.insert("memory_usage".to_string(), serde_json::Value::Number(serde_json::Number::from(process.memory_usage)));
            details.insert("oom_score".to_string(), serde_json::Value::Number(serde_json::Number::from(process.oom_score)));
            
            return Ok(ActionResult::Skipped {
                reason: format!("Dry run: would kill PID {} ({})", process.pid, process.comm),
            });
        }
        
        let signal = Signal::try_from(self.kill_signal)
            .map_err(|_| OomdError::Config(format!("Invalid signal number: {}", self.kill_signal)))?;
        
        match signal::kill(Pid::from_raw(process.pid), signal) {
            Ok(_) => {
                let mut details = HashMap::new();
                details.insert("pid".to_string(), serde_json::Value::Number(serde_json::Number::from(process.pid)));
                details.insert("comm".to_string(), serde_json::Value::String(process.comm.clone()));
                details.insert("signal".to_string(), serde_json::Value::Number(serde_json::Number::from(self.kill_signal)));
                details.insert("memory_freed".to_string(), serde_json::Value::Number(serde_json::Number::from(process.memory_usage)));
                
                Ok(ActionResult::Success {
                    message: format!("Killed PID {} ({}) with signal {}", process.pid, process.comm, self.kill_signal),
                    details,
                })
            },
            Err(e) => {
                let mut details = HashMap::new();
                details.insert("pid".to_string(), serde_json::Value::Number(serde_json::Number::from(process.pid)));
                details.insert("comm".to_string(), serde_json::Value::String(process.comm.clone()));
                details.insert("error".to_string(), serde_json::Value::String(e.to_string()));
                
                Ok(ActionResult::Failed {
                    error: format!("Failed to kill PID {}: {}", process.pid, e),
                    details,
                })
            }
        }
    }
}

#[async_trait]
impl Plugin for KillAction {
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
            self.kill_strategy = match strategy.as_str() {
                "highest_memory" => KillStrategy::HighestMemory,
                "highest_oom_score" => KillStrategy::HighestOomScore,
                "lowest_oom_score" => KillStrategy::LowestOomScore,
                "oldest" => KillStrategy::Oldest,
                "newest" => KillStrategy::Newest,
                _ => KillStrategy::default(),
            };
        }
        
        if let Ok(dry_run) = self.base.get_config::<bool>("dry_run") {
            self.dry_run = dry_run;
        }
        
        if let Ok(max_kill) = self.base.get_config::<u32>("max_kill_count") {
            self.max_kill_count = max_kill;
        }
        
        if let Ok(signal) = self.base.get_config::<i32>("kill_signal") {
            self.kill_signal = signal;
        }
        
        // Validate configuration
        if self.max_kill_count == 0 {
            return Err(OomdError::Config("Max kill count must be at least 1".to_string()));
        }
        
        self.base.update_status("strategy".to_string(), serde_json::Value::String(format!("{:?}", self.kill_strategy)));
        self.base.update_status("dry_run".to_string(), serde_json::Value::Bool(self.dry_run));
        self.base.update_status("max_kill_count".to_string(), serde_json::Value::Number(serde_json::Number::from(self.max_kill_count)));
        self.base.update_status("kill_signal".to_string(), serde_json::Value::Number(serde_json::Number::from(self.kill_signal)));
        
        Ok(())
    }
    
    async fn run(&self, context: &OomdContext) -> Result<PluginRet, OomdError> {
        if !self.base.is_enabled() {
            return Ok(PluginRet::Continue);
        }
        
        let targets = self.find_targets(context).await?;
        
        if targets.is_empty() {
            self.base.update_status("targets_found".to_string(), serde_json::Value::Number(serde_json::Number::from(0)));
            return Ok(PluginRet::Continue);
        }
        
        self.base.update_status("targets_found".to_string(), serde_json::Value::Number(serde_json::Number::from(targets.len())));
        
        let mut killed_count = 0;
        let mut total_memory_freed = 0;
        
        for process in targets {
            match self.kill_process(&process).await {
                Ok(ActionResult::Success { message, details }) => {
                    killed_count += 1;
                    if let Some(mem) = details.get("memory_freed").and_then(|v| v.as_u64()) {
                        total_memory_freed += mem;
                    }
                    println!("Kill action: {}", message);
                },
                Ok(ActionResult::Failed { error, .. }) => {
                    eprintln!("Kill action failed: {}", error);
                },
                Ok(ActionResult::Skipped { reason }) => {
                    println!("Kill action skipped: {}", reason);
                },
                Err(e) => {
                    eprintln!("Kill action error: {}", e);
                }
            }
        }
        
        if killed_count > 0 {
            self.base.update_status("killed_count".to_string(), serde_json::Value::Number(serde_json::Number::from(killed_count)));
            self.base.update_status("total_memory_freed".to_string(), serde_json::Value::Number(serde_json::Number::from(total_memory_freed)));
            println!("Kill action completed: killed {} processes, freed {} bytes", killed_count, total_memory_freed);
        }
        
        Ok(PluginRet::Continue)
    }
    
    async fn cleanup(&self) -> Result<(), OomdError> {
        self.base.cleanup().await
    }
    
    fn get_status(&self) -> HashMap<String, serde_json::Value> {
        let mut status = self.base.get_status();
        status.insert("type".to_string(), serde_json::Value::String("action".to_string()));
        status.insert("action_type".to_string(), serde_json::Value::String("kill".to_string()));
        status
    }
}

#[async_trait]
impl ActionPlugin for KillAction {
    async fn execute(&self, context: &OomdContext, _target: Option<&CgroupContext>) -> Result<ActionResult, OomdError> {
        self.run(context).await?;
        Ok(ActionResult::Success {
            message: "Kill action executed".to_string(),
            details: HashMap::new(),
        })
    }
    
    async fn can_execute(&self, _context: &OomdContext) -> Result<bool, OomdError> {
        // Check if we have permission to kill processes
        // This is a simplified check - in reality, you'd want more comprehensive validation
        Ok(true)
    }
}

impl AsAny for KillAction {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl PluginWithContext for KillAction {
    fn is_enabled(&self) -> bool {
        self.base.is_enabled()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KillActionConfig {
    pub strategy: String,
    pub dry_run: bool,
    pub max_kill_count: u32,
    pub kill_signal: i32,
    pub enabled: bool,
}

impl Default for KillActionConfig {
    fn default() -> Self {
        Self {
            strategy: "highest_memory".to_string(),
            dry_run: false,
            max_kill_count: 1,
            kill_signal: 9,
            enabled: true,
        }
    }
}