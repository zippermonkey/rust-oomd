

  use super::types::*;
  use super::core::types::*;

  #[async_trait::async_trait]
  pub trait CgroupInterface: Send + Sync {
      /// 获取cgroup版本
      fn version(&self) -> &CgroupVersion;

      /// 获取内存压力
      async fn get_memory_pressure(&self, cgroup: &CgroupPath) -> Result<ResourcePressure>;

      /// 获取内存使用量
      async fn get_memory_usage(&self, cgroup: &CgroupPath) -> Result<u64>;

      /// 获取内存限制
      async fn get_memory_limit(&self, cgroup: &CgroupPath) -> Result<u64>;

      /// 获取IO压力
      async fn get_io_pressure(&self, cgroup: &CgroupPath) -> Result<ResourcePressure>;

      /// 获取内存统计信息
      async fn get_memory_stat(&self, cgroup: &CgroupPath) -> Result<MemoryStat>;

      /// 获取IO统计信息
      async fn get_io_stat(&self, cgroup: &CgroupPath) -> Result<IOStat>;

      /// 获取进程列表
      async fn get_pids(&self, cgroup: &CgroupPath) -> Result<Vec<libc::pid_t>>;

      /// 获取子cgroup列表
      async fn get_children(&self, cgroup: &CgroupPath) -> Result<Vec<String>>;

      /// 检查cgroup是否被占用
      async fn is_populated(&self, cgroup: &CgroupPath) -> Result<bool>;

      /// 内存回收
      async fn memory_reclaim(&self, cgroup: &CgroupPath, amount: u64) -> Result<()>;

      /// 列出匹配的cgroup
      async fn list_cgroups(&self, pattern: &str) -> Result<Vec<CgroupPath>>;

      /// 检查cgroup是否存在
      async fn cgroup_exists(&self, cgroup: &CgroupPath) -> Result<bool>;

      /// 获取系统级内存压力
      async fn get_system_memory_pressure(&self) -> Result<ResourcePressure>;

      /// 获取系统级IO压力
      async fn get_system_io_pressure(&self) -> Result<ResourcePressure>;
  }

  /// 压力类型枚举
  #[derive(Debug, Clone, Copy, PartialEq)]
  pub enum PressureType {
      Some,   // 部分阻塞
      Full,   // 完全阻塞
  }

  impl PressureType {
      pub fn as_str(&self) -> &'static str {
          match self {
              PressureType::Some => "some",
              PressureType::Full => "full",
          }
      }
  }

  /// PSI数据格式
  #[derive(Debug, Clone, PartialEq)]
  pub struct PsiData {
      pub avg10: f32,
      pub avg60: f32,
      pub avg300: f32,
      pub total: Option<u64>,  // 微秒
  }

  impl PsiData {
      pub fn from_line(line: &str) -> Result<Self> {
          // 解析PSI格式: "some avg10=0.22 avg60=0.17 avg300=1.11 total=58761459"
          let parts: Vec<&str> = line.split_whitespace().collect();
          if parts.len() < 4 {
              return Err(OomdError::Parse(format!("Invalid PSI format: {}", line)));
          }

          let avg10 = Self::parse_float_field(parts[1])?;
          let avg60 = Self::parse_float_field(parts[2])?;
          let avg300 = Self::parse_float_field(parts[3])?;
          let total = if parts.len() > 4 {
              Self::parse_u64_field(parts[4])?.ok()
          } else {
              None
          };

          Ok(Self {
              avg10,
              avg60,
              avg300,
              total,
          })
      }

      fn parse_float_field(field: &str) -> Result<f32> {
          let kv: Vec<&str> = field.split('=').collect();
          if kv.len() != 2 {
              return Err(OomdError::Parse(format!("Invalid field format: {}", field)));
          }
          kv[1].parse().map_err(|e| OomdError::Parse(e.to_string()))
      }

      fn parse_u64_field(field: &str) -> Result<Option<u64>> {
          let kv: Vec<&str> = field.split('=').collect();
          if kv.len() != 2 {
              return Err(OomdError::Parse(format!("Invalid field format: {}", field)));
          }
          match kv[1].parse() {
              Ok(v) => Ok(Some(v)),
              Err(_) => Ok(None),
          }
      }

      pub fn to_resource_pressure(&self) -> ResourcePressure {
          ResourcePressure {
              sec_10: self.avg10,
              sec_60: self.avg60,
              sec_300: self.avg300,
              total: self.total.map(Duration::from_micros),
          }
      }
  }
