use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{RwLock, Mutex};
use once_cell::sync::Lazy;
use serde_json;
use crate::error::Result;

static SNI_RULES: Lazy<RwLock<HashMap<String, String>>> = Lazy::new(|| RwLock::new(HashMap::new()));
static SNI_RULES_PATH: Lazy<Mutex<Option<PathBuf>>> = Lazy::new(|| Mutex::new(None));

pub fn set_storage_path(path: PathBuf) {
    let mut guard = SNI_RULES_PATH.lock().unwrap();
    *guard = Some(path);
    if let Some(p) = guard.as_ref() {
        load_from_file(p).ok();
    }
}

fn load_from_file(path: &PathBuf) -> Result<()> {
    let content = std::fs::read_to_string(path)?;
    let rules: HashMap<String, String> = serde_json::from_str(&content)?;
    let mut guard = SNI_RULES.write().unwrap();
    *guard = rules;
    log::info!("Loaded {} SNI rules", guard.len());
    Ok(())
}

fn save_to_file() -> Result<()> {
    let guard = SNI_RULES_PATH.lock().unwrap();
    if let Some(path) = guard.as_ref() {
        let rules = SNI_RULES.read().unwrap();
        let json = serde_json::to_string_pretty(&*rules)?;
        std::fs::write(path, json)?;
        log::info!("Saved {} SNI rules", rules.len());
    }
    Ok(())
}

pub fn set_rule(domain: &str, replacement: &str) -> Result<()> {
    let mut rules = SNI_RULES.write().unwrap();
    rules.insert(domain.to_string(), replacement.to_string());
    log::info!("SNI rule added: {} -> {}", domain, replacement);
    drop(rules);
    save_to_file()?;
    Ok(())
}

pub fn remove_rule(domain: &str) -> Result<()> {
    let mut rules = SNI_RULES.write().unwrap();
    if rules.remove(domain).is_some() {
        log::info!("SNI rule removed: {}", domain);
        drop(rules);
        save_to_file()?;
    }
    Ok(())
}

pub fn get_replacement(domain: &str) -> Option<String> {
    let rules = SNI_RULES.read().unwrap();
    rules.get(domain).cloned()
}

pub fn get_all_rules() -> HashMap<String, String> {
    SNI_RULES.read().unwrap().clone()
}
