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

pub struct CgroupV1Interface {
    memory_mount: PathBuf,
    cpu_mount: PathBuf,
    blkio_mount: PathBuf,
    cpuset_mount: PathBuf,
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

impl CgroupV1Interface {
    pub async fn new() -> Result<Self, super::util::error::OomdError> {
        let memory_mount = Self::find_mount_point("memory")?;
        let cpu_mount = Self::find_mount_point("cpu")?;
        let blkio_mount = Self::find_mount_point("blkio")?;
        let cpuset_mount = Self::find_mount_point("cpuset")?;
        
        Ok(Self {
            memory_mount,
            cpu_mount,
            blkio_mount,
            cpuset_mount,
            cache: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        })
    }
    
    fn find_mount_point(subsystem: &str) -> Result<PathBuf, super::util::error::OomdError> {
        let content = fs::read_to_string("/proc/mounts")?;
        
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[2] == "cgroup" {
                let opts: Vec<&str> = parts[3].split(',').collect();
                if opts.contains(&subsystem) {
                    return Ok(PathBuf::from(parts[1]));
                }
            }
        }
        
        Err(super::util::error::OomdError::CgroupNotFound(format!("{} subsystem not found", subsystem)))
    }
    
    fn get_memory_cgroup_path(&self, cgroup: &CgroupPath) -> PathBuf {
        self.memory_mount.join(&cgroup.relative_path)
    }
    
    fn get_blkio_cgroup_path(&self, cgroup: &CgroupPath) -> PathBuf {
        self.blkio_mount.join(&cgroup.relative_path)
    }
    
    async fn get_cache<T>(&self, key: &str, ttl: std::time::Duration, f: impl std::future::Future<Output = Result<T, super::util::error::OomdError>>) -> Result<T, super::util::error::OomdError> {
        let cache = self.cache.read().await;
        
        if let Some(entry) = cache.get(key) {
            if entry.timestamp.elapsed() < ttl {
                match &entry.data {
                    CachedData::MemoryPressure(data) => return Ok(data.clone()),
                    CachedData::MemoryUsage(data) => return Ok(*data),
                    CachedData::MemoryLimit(data) => return Ok(*data),
                    _ => {}
                }
            }
        }
        
        drop(cache);
        
        let data = f.await?;
        
        let entry = CacheEntry {
            data: match &data {
                d if std::any::type_name::<T>() == std::any::type_name::<ResourcePressure>() => {
                    CachedData::MemoryPressure(unsafe { std::mem::transmute_copy(&data) })
                },
                d if std::any::type_name::<T>() == std::any::type_name::<u64>() => {
                    CachedData::MemoryUsage(unsafe { std::mem::transmute_copy(&data) })
                },
                _ => return Err(super::util::error::OomdError::System("Unsupported cache type".to_string())),
            },
            timestamp: std::time::Instant::now(),
            ttl,
        };
        
        self.cache.write().await.insert(key.to_string(), entry);
        Ok(data)
    }
    
    /// 0��X�� - v1�	�PSI/
    async fn estimate_memory_pressure(&self, cgroup: &CgroupPath) -> Result<ResourcePressure, super::util::error::OomdError> {
        let usage = self.get_memory_usage(cgroup).await?;
        let limit = self.get_memory_limit(cgroup).await?;
        let usage_ratio = usage as f64 / limit as f64;
        
        // ���ߧPSI
        let system_psi = self.get_system_memory_pressure().await?;
        
        // ��(�t��PSI
        let estimated_psi = ResourcePressure {
            sec_10: system_psi.sec_10 * usage_ratio as f32,
            sec_60: system_psi.sec_60 * usage_ratio as f32,
            sec_300: system_psi.sec_300 * usage_ratio as f32,
            total: system_psi.total,
        };
        
        Ok(estimated_psi)
    }
    
    /// �vmstat���߅X���o
    async fn get_vmstat_pressure(&self) -> Result<ResourcePressure, super::util::error::OomdError> {
        let vmstat_content = fs::read_to_string("/proc/vmstat")?;
        let mut pgscan = 0u64;
        let mut pgsteal = 0u64;
        
        for line in vmstat_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                match parts[0] {
                    "pgscan_kswapd" | "pgscan_direct" => {
                        pgscan += parts[1].parse::<u64>().unwrap_or(0);
                    }
                    "pgsteal_kswapd" | "pgsteal_direct" => {
                        pgsteal += parts[1].parse::<u64>().unwrap_or(0);
                    }
                    _ => continue,
                }
            }
        }
        
        // ��kό��ԋ����
        let steal_ratio = if pgscan > 0 { pgsteal as f64 / pgscan as f64 } else { 0.0 };
        let pressure_10 = (steal_ratio * 100.0).min(100.0) as f32;
        let pressure_60 = pressure_10 * 0.8; // 60�sGeN
        let pressure_300 = pressure_10 * 0.6; // 300�sG�N
        
        Ok(ResourcePressure {
            sec_10: pressure_10,
            sec_60: pressure_60,
            sec_300: pressure_300,
            total: None,
        })
    }
    
    /// �օX�6��
    async fn read_memory_file(&self, cgroup: &CgroupPath, filename: &str) -> Result<String, super::util::error::OomdError> {
        let path = self.get_memory_cgroup_path(cgroup).join(filename);
        let content = async_fs::read_to_string(&path).await
            .map_err(|e| super::util::error::OomdError::Io(e))?;
        Ok(content.trim().to_string())
    }
    
    /// ��blkio�6��
    async fn read_blkio_file(&self, cgroup: &CgroupPath, filename: &str) -> Result<String, super::util::error::OomdError> {
        let path = self.get_blkio_cgroup_path(cgroup).join(filename);
        let content = async_fs::read_to_string(&path).await
            .map_err(|e| super::util::error::OomdError::Io(e))?;
        Ok(content.trim().to_string())
    }
}

#[async_trait]
impl super::interface::CgroupInterface for CgroupV1Interface {
    fn version(&self) -> &super::types::CgroupVersion {
        &super::types::CgroupVersion::V1 {
            memory: self.memory_mount.clone(),
            cpu: self.cpu_mount.clone(),
            blkio: self.blkio_mount.clone(),
            cpuset: self.cpuset_mount.clone(),
        }
    }
    
    async fn get_memory_pressure(&self, cgroup: &CgroupPath) -> Result<ResourcePressure, super::util::error::OomdError> {
        let key = format!("memory_pressure:{}", cgroup.relative_path);
        self.get_cache(&key, std::time::Duration::from_secs(2), async {
            self.estimate_memory_pressure(cgroup).await
        }).await
    }
    
    async fn get_memory_usage(&self, cgroup: &CgroupPath) -> Result<u64, super::util::error::OomdError> {
        let key = format!("memory_usage:{}", cgroup.relative_path);
        self.get_cache(&key, std::time::Duration::from_secs(1), async {
            let content = self.read_memory_file(cgroup, "memory.usage_in_bytes").await?;
            content.parse().map_err(|e| super::util::error::OomdError::Parse(e.to_string()))
        }).await
    }
    
    async fn get_memory_limit(&self, cgroup: &CgroupPath) -> Result<u64, super::util::error::OomdError> {
        let key = format!("memory_limit:{}", cgroup.relative_path);
        self.get_cache(&key, std::time::Duration::from_secs(5), async {
            let content = self.read_memory_file(cgroup, "memory.limit_in_bytes").await?;
            match content.parse::<u64>() {
                Ok(limit) => Ok(limit),
                Err(_) => {
                    // Some systems use "max" for unlimited
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
        // cgroup v1 doesn't have native IO pressure, estimate from blkio stats
        let key = format!("io_pressure:{}", cgroup.relative_path);
        self.get_cache(&key, std::time::Duration::from_secs(2), async {
            let io_stat = self.get_io_stat(cgroup).await?;
            let total_ios = io_stat.rios + io_stat.wios;
            let total_bytes = io_stat.rbytes + io_stat.wbytes;
            
            // Simple pressure estimation based on I/O activity
            let pressure_10 = if total_ios > 1000 { 80.0 } else if total_ios > 100 { 50.0 } else { 10.0 };
            let pressure_60 = pressure_10 * 0.8;
            let pressure_300 = pressure_10 * 0.6;
            
            Ok(ResourcePressure {
                sec_10: pressure_10,
                sec_60: pressure_60,
                sec_300: pressure_300,
                total: None,
            })
        }).await
    }
    
    async fn get_memory_stat(&self, cgroup: &CgroupPath) -> Result<MemoryStat, super::util::error::OomdError> {
        let key = format!("memory_stat:{}", cgroup.relative_path);
        self.get_cache(&key, std::time::Duration::from_secs(5), async {
            let content = self.read_memory_file(cgroup, "memory.stat").await?;
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
            
            // Read blkio.io_service_bytes
            if let Ok(content) = self.read_blkio_file(cgroup, "blkio.io_service_bytes").await {
                for line in content.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() == 3 && parts[0] == "Total" {
                        match parts[1] {
                            "Read" => stat.rbytes = parts[2].parse().unwrap_or(0),
                            "Write" => stat.wbytes = parts[2].parse().unwrap_or(0),
                            _ => {}
                        }
                    }
                }
            }
            
            // Read blkio.io_serviced
            if let Ok(content) = self.read_blkio_file(cgroup, "blkio.io_serviced").await {
                for line in content.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() == 3 && parts[0] == "Total" {
                        match parts[1] {
                            "Read" => stat.rios = parts[2].parse().unwrap_or(0),
                            "Write" => stat.wios = parts[2].parse().unwrap_or(0),
                            _ => {}
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
            let path = self.get_memory_cgroup_path(cgroup).join("cgroup.procs");
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
            let path = self.get_memory_cgroup_path(cgroup);
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
            let pids = self.get_pids(cgroup).await?;
            Ok(!pids.is_empty())
        }).await
    }
    
    async fn memory_reclaim(&self, cgroup: &CgroupPath, amount: u64) -> Result<(), super::util::error::OomdError> {
        let path = self.get_memory_cgroup_path(cgroup).join("memory.force_empty");
        let content = amount.to_string();
        
        async_fs::write(&path, content).await
            .map_err(|e| super::util::error::OomdError::Io(e))?;
        
        Ok(())
    }
    
    async fn list_cgroups(&self, pattern: &str) -> Result<Vec<CgroupPath>, super::util::error::OomdError> {
        let mut cgroups = Vec::new();
        self.find_cgroups_recursive(&self.memory_mount, "", pattern, &mut cgroups).await?;
        Ok(cgroups)
    }
    
    async fn cgroup_exists(&self, cgroup: &CgroupPath) -> Result<bool, super::util::error::OomdError> {
        let path = self.get_memory_cgroup_path(cgroup);
        async_fs::metadata(&path).await
            .map(|_| true)
            .map_err(|_| super::util::error::OomdError::CgroupNotFound(cgroup.relative_path.clone()))
    }
    
    async fn get_system_memory_pressure(&self) -> Result<ResourcePressure, super::util::error::OomdError> {
        let key = "system_memory_pressure";
        self.get_cache(&key, std::time::Duration::from_secs(1), async {
            self.get_vmstat_pressure().await
        }).await
    }
    
    async fn get_system_io_pressure(&self) -> Result<ResourcePressure, super::util::error::OomdError> {
        // For cgroup v1, estimate system IO pressure from vmstat
        let key = "system_io_pressure";
        self.get_cache(&key, std::time::Duration::from_secs(1), async {
            let vmstat_content = fs::read_to_string("/proc/vmstat")?;
            let mut nr_dirty = 0u64;
            let mut nr_writeback = 0u64;
            
            for line in vmstat_content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() == 2 {
                    match parts[0] {
                        "nr_dirty" => nr_dirty = parts[1].parse().unwrap_or(0),
                        "nr_writeback" => nr_writeback = parts[1].parse().unwrap_or(0),
                        _ => continue,
                    }
                }
            }
            
            let total_io = nr_dirty + nr_writeback;
            let pressure_10 = if total_io > 10000 { 90.0 } else if total_io > 1000 { 60.0 } else { 20.0 };
            let pressure_60 = pressure_10 * 0.8;
            let pressure_300 = pressure_10 * 0.6;
            
            Ok(ResourcePressure {
                sec_10: pressure_10,
                sec_60: pressure_60,
                sec_300: pressure_300,
                total: None,
            })
        }).await
    }
}

impl CgroupV1Interface {
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
                            let cgroup_path = CgroupPath::new(self.memory_mount.clone(), base_path.join(&new_path))?;
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