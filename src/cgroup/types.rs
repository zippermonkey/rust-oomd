
  use std::path::PathBuf;
  use super::core::types::ResourcePressure;

  #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
  pub enum CgroupVersion {
      /// Cgroup v1 - 多个挂载点
      V1 {
          memory: PathBuf,
          cpu: PathBuf,
          blkio: PathBuf,
          cpuset: PathBuf,
      },
      /// Cgroup v2 - 统一层次
      V2 {
          unified: PathBuf,
      },
      /// 混合模式 - 同时支持v1和v2
      Hybrid {
          v1_root: PathBuf,
          v2_root: PathBuf,
      },
  }

  impl CgroupVersion {
      pub fn detect() -> Result<Self> {
          // 实现版本检测逻辑
          todo!()
      }

      pub fn supports_psi(&self) -> bool {
          match self {
              CgroupVersion::V1 { .. } => false,  // v1需要特殊处理
              CgroupVersion::V2 { .. } => true,
              CgroupVersion::Hybrid { .. } => true,
          }
      }
  }

  #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
  pub struct CgroupPath {
      pub root: PathBuf,
      pub path: PathBuf,
      pub relative_path: String,
  }

  impl CgroupPath {
      pub fn new(root: PathBuf, path: PathBuf) -> Result<Self> {
          let relative_path = path.strip_prefix(&root)
              .map_err(|_| OomdError::InvalidPath(path.clone()))?
              .to_string_lossy()
              .to_string();

          Ok(Self {
              root,
              path,
              relative_path,
          })
      }

      pub fn absolute(&self) -> &PathBuf {
          &self.path
      }

      pub fn relative(&self) -> &str {
          &self.relative_path
      }
  }

  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct CgroupContext {
      pub path: CgroupPath,
      pub memory_usage: Option<u64>,
      pub memory_limit: Option<u64>,
      pub memory_pressure: Option<ResourcePressure>,
      pub io_pressure: Option<ResourcePressure>,
      pub memory_stat: Option<MemoryStat>,
      pub io_stat: Option<IOStat>,
      pub pids: Option<Vec<libc::pid_t>>,
      pub children: Option<Vec<String>>,
      pub is_populated: Option<bool>,
      pub current_age: Option<u64>,  // 更新次数，用于缓存
  }

  impl CgroupContext {
      pub fn new(path: CgroupPath) -> Self {
          Self {
              path,
              memory_usage: None,
              memory_limit: None,
              memory_pressure: None,
              io_pressure: None,
              memory_stat: None,
              io_stat: None,
              pids: None,
              children: None,
              is_populated: None,
              current_age: 0,
          }
      }

      pub fn is_valid(&self) -> bool {
          self.memory_usage.is_some() || self.memory_pressure.is_some()
      }
  }

  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct OomdContext {
      pub cgroups: std::collections::HashMap<String, CgroupContext>,
      pub system_context: SystemContext,
      pub timestamp: std::time::SystemTime,
      pub cache_age: u64,
  }

  impl OomdContext {
      pub fn new() -> Self {
          Self {
              cgroups: std::collections::HashMap::new(),
              system_context: SystemContext {
                  swaptotal: 0,
                  swapused: 0,
                  swappiness: 60,
                  vmstat: std::collections::HashMap::new(),
                  swapout_bps: 0.0,
                  swapout_bps_60: 0.0,
                  swapout_bps_300: 0.0,
              },
              timestamp: std::time::SystemTime::now(),
              cache_age: 0,
          }
      }

      pub fn get_cgroup(&self, path: &str) -> Option<&CgroupContext> {
          self.cgroups.get(path)
      }

      pub fn get_mut_cgroup(&mut self, path: &str) -> Option<&mut CgroupContext> {
          self.cgroups.get_mut(path)
      }

      pub fn add_cgroup(&mut self, key: String, cgroup: CgroupContext) {
          self.cgroups.insert(key, cgroup);
      }
  }

  