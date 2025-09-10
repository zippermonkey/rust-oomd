use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use crate::plugins::interface::*;
use crate::util::error::OomdError;

/// Plugin registry for managing available plugins
pub struct PluginRegistry {
    plugins: HashMap<String, Arc<dyn Plugin>>,
    detectors: HashMap<String, Arc<dyn DetectorPlugin>>,
    actions: HashMap<String, Arc<dyn ActionPlugin>>,
    metadata: HashMap<String, PluginMetadata>,
}

impl PluginRegistry {
    /// Create a new plugin registry
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            detectors: HashMap::new(),
            actions: HashMap::new(),
            metadata: HashMap::new(),
        }
    }
    
    /// Register a plugin
    pub fn register_plugin<P>(&mut self, plugin: P) -> Result<(), OomdError>
    where
        P: Plugin + 'static,
    {
        let name = plugin.name().to_string();
        let arc_plugin = Arc::new(plugin);
        
        // Add to general plugins
        self.plugins.insert(name.clone(), arc_plugin.clone() as Arc<dyn Plugin>);
        
        // Add to specific type registries if applicable
        if let Some(detector) = (arc_plugin.clone() as Arc<dyn Plugin>).as_any().downcast_ref::<Arc<dyn DetectorPlugin>>() {
            self.detectors.insert(name.clone(), detector.clone());
        }
        
        if let Some(action) = (arc_plugin.clone() as Arc<dyn Plugin>).as_any().downcast_ref::<Arc<dyn ActionPlugin>>() {
            self.actions.insert(name.clone(), action.clone());
        }
        
        Ok(())
    }
    
    /// Register a detector plugin
    pub fn register_detector<D>(&mut self, detector: D) -> Result<(), OomdError>
    where
        D: DetectorPlugin + 'static,
    {
        let name = detector.name().to_string();
        let arc_detector = Arc::new(detector);
        
        self.plugins.insert(name.clone(), arc_detector.clone() as Arc<dyn Plugin>);
        self.detectors.insert(name.clone(), arc_detector);
        
        Ok(())
    }
    
    /// Register an action plugin
    pub fn register_action<A>(&mut self, action: A) -> Result<(), OomdError>
    where
        A: ActionPlugin + 'static,
    {
        let name = action.name().to_string();
        let arc_action = Arc::new(action);
        
        self.plugins.insert(name.clone(), arc_action.clone() as Arc<dyn Plugin>);
        self.actions.insert(name.clone(), arc_action);
        
        Ok(())
    }
    
    /// Get a plugin by name
    pub fn get_plugin(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.plugins.get(name).cloned()
    }
    
    /// Get a detector plugin by name
    pub fn get_detector(&self, name: &str) -> Option<Arc<dyn DetectorPlugin>> {
        self.detectors.get(name).cloned()
    }
    
    /// Get an action plugin by name
    pub fn get_action(&self, name: &str) -> Option<Arc<dyn ActionPlugin>> {
        self.actions.get(name).cloned()
    }
    
    /// List all registered plugins
    pub fn list_plugins(&self) -> Vec<String> {
        self.plugins.keys().cloned().collect()
    }
    
    /// List all detector plugins
    pub fn list_detectors(&self) -> Vec<String> {
        self.detectors.keys().cloned().collect()
    }
    
    /// List all action plugins
    pub fn list_actions(&self) -> Vec<String> {
        self.actions.keys().cloned().collect()
    }
    
    /// Get plugin metadata
    pub fn get_metadata(&self, name: &str) -> Option<&PluginMetadata> {
        self.metadata.get(name)
    }
    
    /// Check if a plugin is registered
    pub fn has_plugin(&self, name: &str) -> bool {
        self.plugins.contains_key(name)
    }
    
    /// Check if a detector plugin is registered
    pub fn has_detector(&self, name: &str) -> bool {
        self.detectors.contains_key(name)
    }
    
    /// Check if an action plugin is registered
    pub fn has_action(&self, name: &str) -> bool {
        self.actions.contains_key(name)
    }
    
    /// Unregister a plugin
    pub fn unregister_plugin(&mut self, name: &str) -> Result<(), OomdError> {
        self.plugins.remove(name);
        self.detectors.remove(name);
        self.actions.remove(name);
        self.metadata.remove(name);
        Ok(())
    }
    
    /// Get all plugins of a specific type
    pub fn get_plugins_by_type(&self, plugin_type: PluginType) -> Vec<Arc<dyn Plugin>> {
        self.plugins.values()
            .filter(|plugin| {
                // This is a simplified check - in a real implementation,
                // you'd want to have a method on the Plugin trait to get the type
                match plugin_type {
                    PluginType::Detector => self.detectors.contains_key(&plugin.name().to_string()),
                    PluginType::Action => self.actions.contains_key(&plugin.name().to_string()),
                    PluginType::Hybrid => {
                        let name = plugin.name().to_string();
                        self.detectors.contains_key(&name) && self.actions.contains_key(&name)
                    }
                }
            })
            .cloned()
            .collect()
    }
    
    /// Load plugins from a configuration
    pub async fn load_from_config(&mut self, config: &[PluginConfig]) -> Result<(), OomdError> {
        for plugin_config in config {
            if !plugin_config.enabled {
                continue;
            }
            
            // This is where you would dynamically load plugins
            // For now, we'll just create instances of known plugins
            match plugin_config.plugin_type {
                PluginType::Detector => {
                    // Example: Create a memory pressure detector
                    if plugin_config.name.starts_with("memory_pressure") {
                        let detector = super::detectors::MemoryPressureDetector::new();
                        self.register_detector(detector)?;
                    }
                },
                PluginType::Action => {
                    // Example: Create a kill action
                    if plugin_config.name.starts_with("kill") {
                        let action = super::actions::KillAction::new();
                        self.register_action(action)?;
                    }
                },
                PluginType::Hybrid => {
                    // Hybrid plugins would be handled here
                },
            }
        }
        
        Ok(())
    }
    
    /// Get plugin statistics
    pub fn get_stats(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();
        
        stats.insert("total_plugins".to_string(), serde_json::Value::Number(serde_json::Number::from(self.plugins.len())));
        stats.insert("total_detectors".to_string(), serde_json::Value::Number(serde_json::Number::from(self.detectors.len())));
        stats.insert("total_actions".to_string(), serde_json::Value::Number(serde_json::Number::from(self.actions.len())));
        
        stats
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin registry instance (singleton pattern)
pub struct GlobalPluginRegistry {
    inner: RwLock<PluginRegistry>,
}

impl GlobalPluginRegistry {
    /// Get the global plugin registry instance
    pub fn get() -> &'static Self {
        static INSTANCE: GlobalPluginRegistry = GlobalPluginRegistry {
            inner: RwLock::new(PluginRegistry::new()),
        };
        &INSTANCE
    }
    
    /// Register a plugin globally
    pub fn register_plugin<P>(&self, plugin: P) -> Result<(), OomdError>
    where
        P: Plugin + 'static,
    {
        let mut registry = self.inner.write().unwrap();
        registry.register_plugin(plugin)
    }
    
    /// Get a plugin by name
    pub fn get_plugin(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        let registry = self.inner.read().unwrap();
        registry.get_plugin(name)
    }
    
    /// List all plugins
    pub fn list_plugins(&self) -> Vec<String> {
        let registry = self.inner.read().unwrap();
        registry.list_plugins()
    }
}

// Helper trait for downcasting
pub trait AsAny: Send + Sync {
    fn as_any(&self) -> &dyn std::any::Any;
}

impl<T: Plugin + 'static> AsAny for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Plugin for Arc<dyn Plugin> {
    fn name(&self) -> &str {
        self.as_ref().name()
    }
    
    fn version(&self) -> &str {
        self.as_ref().version()
    }
    
    fn description(&self) -> &str {
        self.as_ref().description()
    }
    
    async fn init(&mut self, config: &serde_json::Value) -> Result<(), crate::util::error::OomdError> {
        // Arc plugins can't be modified, so this is a no-op
        Ok(())
    }
    
    async fn run(&self, context: &crate::cgroup::types::OomdContext) -> Result<PluginRet, crate::util::error::OomdError> {
        self.as_ref().run(context).await
    }
    
    async fn cleanup(&self) -> Result<(), crate::util::error::OomdError> {
        self.as_ref().cleanup().await
    }
    
    fn get_status(&self) -> HashMap<String, serde_json::Value> {
        self.as_ref().get_status()
    }
}

impl AsAny for Arc<dyn Plugin> {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}