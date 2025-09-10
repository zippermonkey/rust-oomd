use super::interface::*;
use super::types::*;
use super::core::types::*;
use nix::sys::statfs;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use std::os::unix::fs::MetadataExt;
use tokio::fs as async_fs;
use tokio::io::AsyncBufReadExt;

pub struct CgroupV2Interface {
    unified_mount: PathBuf,
    cache: std::sync::Arc<tokio::sync::RwLock<HashMap<String, CacheEntry>>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    data: CachedData,
    timestamp: std::time::Instant,
    ttl: std::time::Duration,
}

#[derive(Debug, Clone)]
enum CachedData {
    MemoryPressure(ResourcePressure),
    MemoryUsage(u64),
    MemoryLimit(u64),
    IOPressure(ResourcePressure),
    MemoryStat(MemoryStat),
    IOStat(IOStat),
    Pids(Vec<libc::pid_t>),
    Children(Vec<String>),
    Populated(bool),
}

impl CgroupV2Interface {
    pub async fn new() -> Result<Self, super::util::error::OomdError> {
        let unified_mount = Self::find_unified_mount()?;
        
        Ok(Self {
            unified_mount,
            cache: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        })
    }
    
    fn find_unified_mount() -> Result<PathBuf, super::util::error::OomdError> {
        let content = fs::read_to_string("/proc/mounts")?;
        
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[2] == "cgroup2" {
                return Ok(PathBuf::from(parts[1]));
            }
        }
        
        Err(super::util::error::OomdError::CgroupNotFound("cgroup2 unified hierarchy not found".to_string()))
    }
    
    fn get_cgroup_path(&self, cgroup: &CgroupPath) -> PathBuf {
        self.unified_mount.join(&cgroup.relative_path)
    }
    
    async fn get_cache<T>(&self, key: &str, ttl: std::time::Duration, f: impl std::future::Future<Output = Result<T, super::util::error::OomdError>>) -> Result<T, super::util::error::OomdError> {
        let cache = self.cache.read().await;
        
        if let Some(entry) = cache.get(key) {
            if entry.timestamp.elapsed() < ttl {
                match &entry.data {
                    CachedData::MemoryPressure(data) => return Ok(data.clone()),
                    CachedData::MemoryUsage(data) => return Ok(*data),
                    CachedData::MemoryLimit(data) => return Ok(*data),
                    CachedData::IOPressure(data) => return Ok(data.clone()),
                    _ => {}
                }
            }
        }
        
        drop(cache);
        
        let data = f.await?;
        
        let entry = CacheEntry {
            data: match &data {
                d if std::any::type_name::<T>() == std::any::type_name::<ResourcePressure>() => {
                    if key.contains("memory") {
                        CachedData::MemoryPressure(unsafe { std::mem::transmute_copy(&data) })
                    } else {
                        CachedData::IOPressure(unsafe { std::mem::transmute_copy(&data) })
                    }
                },
                d if std::any::type_name::<T>() == std::any::type_name::<u64>() => {
                    if key.contains("limit") {
                        CachedData::MemoryLimit(unsafe { std::mem::transmute_copy(&data) })
                    } else {
                        CachedData::MemoryUsage(unsafe { std::mem::transmute_copy(&data) })
                    }
                },
                _ => return Err(super::util::error::OomdError::System("Unsupported cache type".to_string())),
            },
            timestamp: std::time::Instant::now(),
            ttl,
        };
        
        self.cache.write().await.insert(key.to_string(), entry);
        Ok(data)
    }
    
    /// Read PSI data from cgroup v2 interface
    async fn read_psi(&self, cgroup: &CgroupPath, psi_type: PressureType) -> Result<ResourcePressure, super::util::error::OomdError> {
        let filename = match psi_type {
            PressureType::Some => "memory.pressure.some",
            PressureType::Full => "memory.pressure.full",
        };
        
        let path = self.get_cgroup_path(cgroup).join(filename);
        let content = async_fs::read_to_string(&path).await
            .map_err(|e| super::util::error::OomdError::Io(e))?;
        
        let psi_data = PsiData::from_line(&content)?;
        Ok(psi_data.to_resource_pressure())
    }
    
    /// Read system-wide PSI data
    async fn read_system_psi(&self, psi_type: PressureType) -> Result<ResourcePressure, super::util::error::OomdError> {
        let filename = match psi_type {
            PressureType::Some => "/proc/pressure/memory.some",
            PressureType::Full => "/proc/pressure/memory.full",
        };
        
        let content = fs::read_to_string(filename)?;
        let psi_data = PsiData::from_line(&content)?;
        Ok(psi_data.to_resource_pressure())
    }
    
    /// Read cgroup file
    async fn read_cgroup_file(&self, cgroup: &CgroupPath, filename: &str) -> Result<String, super::util::error::OomdError> {
        let path = self.get_cgroup_path(cgroup).join(filename);
        let content = async_fs::read_to_string(&path).await
            .map_err(|e| super::util::error::OomdError::Io(e))?;
        Ok(content.trim().to_string())
    }
    
    /// Read system IO PSI data
    async fn read_system_io_psi(&self, psi_type: PressureType) -> Result<ResourcePressure, super::util::error::OomdError> {
        let filename = match psi_type {
            PressureType::Some => "/proc/pressure/io.some",
            PressureType::Full => "/proc/pressure/io.full",
        };
        
        let content = fs::read_to_string(filename)?;
        let psi_data = PsiData::from_line(&content)?;
        Ok(psi_data.to_resource_pressure())
    }
}

#[async_trait]
impl super::interface::CgroupInterface for CgroupV2Interface {
    fn version(&self) -> &super::types::CgroupVersion {
        &super::types::CgroupVersion::V2 {
            unified: self.unified_mount.clone(),
        }
    }
    
    async fn get_memory_pressure(&self, cgroup: &CgroupPath) -> Result<ResourcePressure, super::util::error::OomdError> {
        let key = format!("memory_pressure:{}", cgroup.relative_path);
        self.get_cache(&key, std::time::Duration::from_secs(2), async {
            // Prefer "full" pressure for memory pressure detection
            self.read_psi(cgroup, PressureType::Full).await
        }).await
    }
    
    async fn get_memory_usage(&self, cgroup: &CgroupPath) -> Result<u64, super::util::error::OomdError> {
        let key = format!("memory_usage:{}", cgroup.relative_path);
        self.get_cache(&key, std::time::Duration::from_secs(1), async {
            let content = self.read_cgroup_file(cgroup, "memory.current").await?;
            content.parse().map_err(|e| super::util::error::OomdError::Parse(e.to_string()))
        }).await
    }
    
    async fn get_memory_limit(&self, cgroup: &CgroupPath) -> Result<u64, super::util::error::OomdError> {
        let key = format!("memory_limit:{}", cgroup.relative_path);
        self.get_cache(&key, std::time::Duration::from_secs(5), async {
            let content = self.read_cgroup_file(cgroup, "memory.max").await?;
            match content.parse::<u64>() {
                Ok(limit) => Ok(limit),
                Err(_) => {
                    // cgroup v2 uses "max" for unlimited
                    if content == "max" {
                        Ok(u64::MAX)
                    } else {
                        Err(super::util::error::OomdError::Parse(format!("Invalid memory limit: {}", content)))
                    }
                }
            }
        }).await
    }
    
    async fn get_io_pressure(&self, cgroup: &CgroupPath) -> Result<ResourcePressure, super::util::error::OomdError> {
        let key = format!("io_pressure:{}", cgroup.relative_path);
        self.get_cache(&key, std::time::Duration::from_secs(2), async {
            // Read IO pressure from cgroup v2
            let path = self.get_cgroup_path(cgroup).join("io.pressure");
            let content = async_fs::read_to_string(&path).await
                .map_err(|e| super::util::error::OomdError::Io(e))?;
            
            // Parse the "full" pressure line
            for line in content.lines() {
                if line.starts_with("full") {
                    let psi_data = PsiData::from_line(line)?;
                    return Ok(psi_data.to_resource_pressure());
                }
            }
            
            // Fallback to "some" pressure if "full" not available
            for line in content.lines() {
                if line.starts_with("some") {
                    let psi_data = PsiData::from_line(line)?;
                    return Ok(psi_data.to_resource_pressure());
                }
            }
            
            Err(super::util::error::OomdError::PressureUnavailable("IO pressure data not available".to_string()))
        }).await
    }
    
    async fn get_memory_stat(&self, cgroup: &CgroupPath) -> Result<MemoryStat, super::util::error::OomdError> {
        let key = format!("memory_stat:{}", cgroup.relative_path);
        self.get_cache(&key, std::time::Duration::from_secs(5), async {
            let content = self.read_cgroup_file(cgroup, "memory.stat").await?;
            let mut stat = MemoryStat::default();
            
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() == 2 {
                    let value = parts[1].parse::<u64>().unwrap_or(0);
                    match parts[0] {
                        "anon" => stat.anon = value,
                        "file" => stat.file = value,
                        "kernel_stack" => stat.kernel_stack = value,
                        "slab" => stat.slab = value,
                        "sock" => stat.sock = value,
                        "shmem" => stat.shmem = value,
                        "file_mapped" => stat.file_mapped = value,
                        "file_dirty" => stat.file_dirty = value,
                        "file_writeback" => stat.file_writeback = value,
                        "anon_thp" => stat.anon_thp = value,
                        "inactive_anon" => stat.inactive_anon = value,
                        "active_anon" => stat.active_anon = value,
                        "inactive_file" => stat.inactive_file = value,
                        "active_file" => stat.active_file = value,
                        "unevictable" => stat.unevictable = value,
                        "slab_reclaimable" => stat.slab_reclaimable = value,
                        "slab_unreclaimable" => stat.slab_unreclaimable = value,
                        "pgfault" => stat.pgfault = value,
                        "pgmajfault" => stat.pgmajfault = value,
                        "workingset_refault" => stat.workingset_refault = value,
                        "workingset_activate" => stat.workingset_activate = value,
                        "workingset_nodereclaim" => stat.workingset_nodereclaim = value,
                        "pgrefill" => stat.pgrefill = value,
                        "pgscan" => stat.pgscan = value,
                        "pgsteal" => stat.pgsteal = value,
                        "pgactivate" => stat.pgactivate = value,
                        "pgdeactivate" => stat.pgdeactivate = value,
                        "pglazyfree" => stat.pglazyfree = value,
                        "pglazyfreed" => stat.pglazyfreed = value,
                        "thp_fault_alloc" => stat.thp_fault_alloc = value,
                        "thp_collapse_alloc" => stat.thp_collapse_alloc = value,
                        _ => {}
                    }
                }
            }
            
            Ok(stat)
        }).await
    }
    
    async fn get_io_stat(&self, cgroup: &CgroupPath) -> Result<IOStat, super::util::error::OomdError> {
        let key = format!("io_stat:{}", cgroup.relative_path);
        self.get_cache(&key, std::time::Duration::from_secs(5), async {
            let mut stat = IOStat::default();
            
            // Read io.stat from cgroup v2
            if let Ok(content) = self.read_cgroup_file(cgroup, "io.stat").await {
                for line in content.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        // Format: "major:minor rbytes=... wbytes=... rios=... wios=... dbytes=... dios=..."
                        for part in parts[1..].iter() {
                            if let Some((key, value)) = part.split_once('=') {
                                let value = value.parse().unwrap_or(0);
                                match key {
                                    "rbytes" => stat.rbytes = value,
                                    "wbytes" => stat.wbytes = value,
                                    "rios" => stat.rios = value,
                                    "wios" => stat.wios = value,
                                    "dbytes" => stat.dbytes = value,
                                    "dios" => stat.dios = value,
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            
            Ok(stat)
        }).await
    }
    
    async fn get_pids(&self, cgroup: &CgroupPath) -> Result<Vec<libc::pid_t>, super::util::error::OomdError> {
        let key = format!("pids:{}", cgroup.relative_path);
        self.get_cache(&key, std::time::Duration::from_secs(2), async {
            let path = self.get_cgroup_path(cgroup).join("cgroup.procs");
            let content = async_fs::read_to_string(&path).await
                .map_err(|e| super::util::error::OomdError::Io(e))?;
            
            let mut pids = Vec::new();
            for line in content.lines() {
                if let Ok(pid) = line.trim().parse::<libc::pid_t>() {
                    pids.push(pid);
                }
            }
            
            Ok(pids)
        }).await
    }
    
    async fn get_children(&self, cgroup: &CgroupPath) -> Result<Vec<String>, super::util::error::OomdError> {
        let key = format!("children:{}", cgroup.relative_path);
        self.get_cache(&key, std::time::Duration::from_secs(10), async {
            let path = self.get_cgroup_path(cgroup);
            let mut entries = async_fs::read_dir(&path).await
                .map_err(|e| super::util::error::OomdError::Io(e))?;
            
            let mut children = Vec::new();
            while let Ok(Some(entry)) = entries.next_entry().await {
                if entry.file_type().await.map(|ft| ft.is_dir()).unwrap_or(false) {
                    if let Some(name) = entry.file_name().to_str() {
                        if !name.starts_with('.') {
                            children.push(name.to_string());
                        }
                    }
                }
            }
            
            Ok(children)
        }).await
    }
    
    async fn is_populated(&self, cgroup: &CgroupPath) -> Result<bool, super::util::error::OomdError> {
        let key = format!("populated:{}", cgroup.relative_path);
        self.get_cache(&key, std::time::Duration::from_secs(5), async {
            let path = self.get_cgroup_path(cgroup).join("cgroup.events");
            let content = async_fs::read_to_string(&path).await
                .map_err(|e| super::util::error::OomdError::Io(e))?;
            
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() == 2 && parts[0] == "populated" {
                    return Ok(parts[1] == "1");
                }
            }
            
            // Fallback to checking if there are any PIDs
            let pids = self.get_pids(cgroup).await?;
            Ok(!pids.is_empty())
        }).await
    }
    
    async fn memory_reclaim(&self, cgroup: &CgroupPath, amount: u64) -> Result<(), super::util::error::OomdError> {
        let path = self.get_cgroup_path(cgroup).join("memory.reclaim");
        let content = amount.to_string();
        
        async_fs::write(&path, content).await
            .map_err(|e| super::util::error::OomdError::Io(e))?;
        
        Ok(())
    }
    
    async fn list_cgroups(&self, pattern: &str) -> Result<Vec<CgroupPath>, super::util::error::OomdError> {
        let mut cgroups = Vec::new();
        self.find_cgroups_recursive(&self.unified_mount, "", pattern, &mut cgroups).await?;
        Ok(cgroups)
    }
    
    async fn cgroup_exists(&self, cgroup: &CgroupPath) -> Result<bool, super::util::error::OomdError> {
        let path = self.get_cgroup_path(cgroup);
        async_fs::metadata(&path).await
            .map(|_| true)
            .map_err(|_| super::util::error::OomdError::CgroupNotFound(cgroup.relative_path.clone()))
    }
    
    async fn get_system_memory_pressure(&self) -> Result<ResourcePressure, super::util::error::OomdError> {
        let key = "system_memory_pressure";
        self.get_cache(&key, std::time::Duration::from_secs(1), async {
            // Prefer "full" pressure for system memory pressure
            self.read_system_psi(PressureType::Full).await
        }).await
    }
    
    async fn get_system_io_pressure(&self) -> Result<ResourcePressure, super::util::error::OomdError> {
        let key = "system_io_pressure";
        self.get_cache(&key, std::time::Duration::from_secs(1), async {
            self.read_system_io_psi(PressureType::Full).await
        }).await
    }
}

impl CgroupV2Interface {
    async fn find_cgroups_recursive(&self, base_path: &Path, current_path: &str, pattern: &str, results: &mut Vec<CgroupPath>) -> Result<(), super::util::error::OomdError> {
        let full_path = base_path.join(current_path);
        let mut entries = async_fs::read_dir(&full_path).await
            .map_err(|e| super::util::error::OomdError::Io(e))?;
        
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.file_type().await.map(|ft| ft.is_dir()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    if !name.starts_with('.') {
                        let new_path = if current_path.is_empty() {
                            name.to_string()
                        } else {
                            format!("{}/{}", current_path, name)
                        };
                        
                        if pattern.is_empty() || new_path.contains(pattern) {
                            let cgroup_path = CgroupPath::new(self.unified_mount.clone(), base_path.join(&new_path))?;
                            results.push(cgroup_path);
                        }
                        
                        self.find_cgroups_recursive(base_path, &new_path, pattern, results).await?;
                    }
                }
            }
        }
        
        Ok(())
    }
}