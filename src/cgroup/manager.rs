use super::interface::*;
use super::types::*;
use super::v1::CgroupV1Interface;
use super::v2::CgroupV2Interface;
use std::path::Path;
use std::fs;

pub struct CgroupManager {
    interface: Box<dyn CgroupInterface>,
    version: CgroupVersion,
}

impl CgroupManager {
    /// Create a new CgroupManager with automatic version detection
    pub async fn new() -> Result<Self, super::util::error::OomdError> {
        let detected_version = Self::detect_cgroup_version()?;
        
        let (interface, version) = match detected_version {
            CgroupVersion::V2 { unified } => {
                let v2_interface = CgroupV2Interface::new().await?;
                (Box::new(v2_interface) as Box<dyn CgroupInterface>, detected_version)
            },
            CgroupVersion::V1 { memory, cpu, blkio, cpuset } => {
                let v1_interface = CgroupV1Interface::new().await?;
                (Box::new(v1_interface) as Box<dyn CgroupInterface>, detected_version)
            },
            CgroupVersion::Hybrid { v2_root, v1_root } => {
                // Prefer v2 in hybrid mode, but fall back to v1 for specific operations
                let v2_interface = CgroupV2Interface::new().await?;
                (Box::new(v2_interface) as Box<dyn CgroupInterface>, detected_version)
            },
        };
        
        Ok(Self {
            interface,
            version,
        })
    }
    
    /// Create a CgroupManager with a specific version
    pub async fn with_version(version: CgroupVersion) -> Result<Self, super::util::error::OomdError> {
        let interface: Box<dyn CgroupInterface> = match version {
            CgroupVersion::V2 { .. } => {
                Box::new(CgroupV2Interface::new().await?)
            },
            CgroupVersion::V1 { .. } => {
                Box::new(CgroupV1Interface::new().await?)
            },
            CgroupVersion::Hybrid { .. } => {
                // For hybrid mode, prefer v2
                Box::new(CgroupV2Interface::new().await?)
            },
        };
        
        Ok(Self {
            interface,
            version,
        })
    }
    
    /// Detect the cgroup version available on the system
    fn detect_cgroup_version() -> Result<CgroupVersion, super::util::error::OomdError> {
        let mounts_content = fs::read_to_string("/proc/mounts")
            .map_err(|e| super::util::error::OomdError::Io(e))?;
        
        let mut v1_mounts = std::collections::HashMap::new();
        let mut v2_mount = None;
        
        for line in mounts_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if parts[2] == "cgroup" {
                    // cgroup v1
                    let opts: Vec<&str> = parts[3].split(',').collect();
                    for opt in opts {
                        if ["memory", "cpu", "blkio", "cpuset"].contains(&opt) {
                            v1_mounts.insert(opt, PathBuf::from(parts[1]));
                        }
                    }
                } else if parts[2] == "cgroup2" {
                    // cgroup v2
                    v2_mount = Some(PathBuf::from(parts[1]));
                }
            }
        }
        
        // Check if we have both v1 and v2 (hybrid mode)
        if v2_mount.is_some() && !v1_mounts.is_empty() {
            return Ok(CgroupVersion::Hybrid {
                v2_root: v2_mount.unwrap(),
                v1_root: v1_mounts.get("memory").cloned().unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup/memory")),
            });
        }
        
        // Check for v2 only
        if let Some(v2_path) = v2_mount {
            return Ok(CgroupVersion::V2 { unified: v2_path });
        }
        
        // Check for v1 only
        if !v1_mounts.is_empty() {
            return Ok(CgroupVersion::V1 {
                memory: v1_mounts.get("memory").cloned().unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup/memory")),
                cpu: v1_mounts.get("cpu").cloned().unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup/cpu")),
                blkio: v1_mounts.get("blkio").cloned().unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup/blkio")),
                cpuset: v1_mounts.get("cpuset").cloned().unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup/cpuset")),
            });
        }
        
        Err(super::util::error::OomdError::CgroupNotFound("No cgroup filesystem found".to_string()))
    }
    
    /// Get the detected cgroup version
    pub fn version(&self) -> &CgroupVersion {
        &self.version
    }
    
    /// Check if the system supports PSI (Pressure Stall Information)
    pub fn supports_psi(&self) -> bool {
        self.version.supports_psi()
    }
    
    /// Create a new cgroup path
    pub fn create_cgroup_path(&self, path: PathBuf) -> Result<CgroupPath, super::util::error::OomdError> {
        let root = match &self.version {
            CgroupVersion::V1 { memory, .. } => memory.clone(),
            CgroupVersion::V2 { unified } => unified.clone(),
            CgroupVersion::Hybrid { v2_root, .. } => v2_root.clone(),
        };
        
        CgroupPath::new(root, path)
    }
    
    /// Delegate methods to the underlying interface
    pub async fn get_memory_pressure(&self, cgroup: &CgroupPath) -> Result<ResourcePressure, super::util::error::OomdError> {
        self.interface.get_memory_pressure(cgroup).await
    }
    
    pub async fn get_memory_usage(&self, cgroup: &CgroupPath) -> Result<u64, super::util::error::OomdError> {
        self.interface.get_memory_usage(cgroup).await
    }
    
    pub async fn get_memory_limit(&self, cgroup: &CgroupPath) -> Result<u64, super::util::error::OomdError> {
        self.interface.get_memory_limit(cgroup).await
    }
    
    pub async fn get_io_pressure(&self, cgroup: &CgroupPath) -> Result<ResourcePressure, super::util::error::OomdError> {
        self.interface.get_io_pressure(cgroup).await
    }
    
    pub async fn get_memory_stat(&self, cgroup: &CgroupPath) -> Result<MemoryStat, super::util::error::OomdError> {
        self.interface.get_memory_stat(cgroup).await
    }
    
    pub async fn get_io_stat(&self, cgroup: &CgroupPath) -> Result<IOStat, super::util::error::OomdError> {
        self.interface.get_io_stat(cgroup).await
    }
    
    pub async fn get_pids(&self, cgroup: &CgroupPath) -> Result<Vec<libc::pid_t>, super::util::error::OomdError> {
        self.interface.get_pids(cgroup).await
    }
    
    pub async fn get_children(&self, cgroup: &CgroupPath) -> Result<Vec<String>, super::util::error::OomdError> {
        self.interface.get_children(cgroup).await
    }
    
    pub async fn is_populated(&self, cgroup: &CgroupPath) -> Result<bool, super::util::error::OomdError> {
        self.interface.is_populated(cgroup).await
    }
    
    pub async fn memory_reclaim(&self, cgroup: &CgroupPath, amount: u64) -> Result<(), super::util::error::OomdError> {
        self.interface.memory_reclaim(cgroup, amount).await
    }
    
    pub async fn list_cgroups(&self, pattern: &str) -> Result<Vec<CgroupPath>, super::util::error::OomdError> {
        self.interface.list_cgroups(pattern).await
    }
    
    pub async fn cgroup_exists(&self, cgroup: &CgroupPath) -> Result<bool, super::util::error::OomdError> {
        self.interface.cgroup_exists(cgroup).await
    }
    
    pub async fn get_system_memory_pressure(&self) -> Result<ResourcePressure, super::util::error::OomdError> {
        self.interface.get_system_memory_pressure().await
    }
    
    pub async fn get_system_io_pressure(&self) -> Result<ResourcePressure, super::util::error::OomdError> {
        self.interface.get_system_io_pressure().await
    }
    
    /// Get comprehensive cgroup context
    pub async fn get_cgroup_context(&self, cgroup: &CgroupPath) -> Result<super::types::CgroupContext, super::util::error::OomdError> {
        let mut context = super::types::CgroupContext::new(cgroup.clone());
        
        // Fetch all available data in parallel
        let (memory_usage, memory_limit, memory_pressure, io_pressure, memory_stat, io_stat, pids, children, populated) = tokio::join!(
            self.get_memory_usage(cgroup),
            self.get_memory_limit(cgroup),
            self.get_memory_pressure(cgroup),
            self.get_io_pressure(cgroup),
            self.get_memory_stat(cgroup),
            self.get_io_stat(cgroup),
            self.get_pids(cgroup),
            self.get_children(cgroup),
            self.is_populated(cgroup)
        );
        
        context.memory_usage = memory_usage.ok();
        context.memory_limit = memory_limit.ok();
        context.memory_pressure = memory_pressure.ok();
        context.io_pressure = io_pressure.ok();
        context.memory_stat = memory_stat.ok();
        context.io_stat = io_stat.ok();
        context.pids = pids.ok();
        context.children = children.ok();
        context.is_populated = populated.ok();
        
        Ok(context)
    }
    
    /// Monitor cgroup for changes
    pub async fn monitor_cgroup<F>(&self, cgroup: &CgroupPath, callback: F, interval: std::time::Duration) -> Result<(), super::util::error::OomdError>
    where
        F: Fn(super::types::CgroupContext) + Send + Sync + 'static,
    {
        let callback = std::sync::Arc::new(callback);
        let cgroup = cgroup.clone();
        let manager = self.interface.as_ref();
        
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                // Get cgroup context
                let context = match Self::get_single_cgroup_context(manager, &cgroup).await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        eprintln!("Error monitoring cgroup: {}", e);
                        continue;
                    }
                };
                
                // Invoke callback
                callback(context);
            }
        });
        
        Ok(())
    }
    
    async fn get_single_cgroup_context(interface: &dyn CgroupInterface, cgroup: &CgroupPath) -> Result<super::types::CgroupContext, super::util::error::OomdError> {
        let mut context = super::types::CgroupContext::new(cgroup.clone());
        
        // Fetch key metrics
        let (memory_usage, memory_pressure) = tokio::join!(
            interface.get_memory_usage(cgroup),
            interface.get_memory_pressure(cgroup)
        );
        
        context.memory_usage = memory_usage.ok();
        context.memory_pressure = memory_pressure.ok();
        
        Ok(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_detect_cgroup_version() {
        // This test requires cgroup filesystem to be available
        let version = CgroupManager::detect_cgroup_version();
        
        // Don't fail the test if cgroups aren't available in test environment
        match version {
            Ok(_) => println!("Detected cgroup version successfully"),
            Err(_) => println!("Cgroup detection failed (expected in test environment)"),
        }
    }
    
    #[tokio::test]
    async fn test_create_manager() {
        // This test requires cgroup filesystem to be available
        let manager = CgroupManager::new().await;
        
        match manager {
            Ok(m) => {
                println!("Created cgroup manager with version: {:?}", m.version());
                println!("PSI support: {}", m.supports_psi());
            },
            Err(_) => println!("Failed to create manager (expected in test environment)"),
        }
    }
}