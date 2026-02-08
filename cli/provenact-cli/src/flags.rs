use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

pub fn parse_flags(
    args: &[String],
    allowed: &[&str],
    usage: &str,
) -> Result<HashMap<String, String>, String> {
    parse_flags_with_switches(args, allowed, &[], usage)
}

pub fn parse_flags_with_switches(
    args: &[String],
    allowed: &[&str],
    switches: &[&str],
    usage: &str,
) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    let allowed_set = allowed.iter().copied().collect::<HashSet<_>>();
    let switch_set = switches.iter().copied().collect::<HashSet<_>>();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        if !allowed_set.contains(flag) && !switch_set.contains(flag) {
            return Err(usage.to_string());
        }
        if switch_set.contains(flag) {
            if out.insert(flag.to_string(), "true".to_string()).is_some() {
                return Err(usage.to_string());
            }
            i += 1;
            continue;
        }
        i += 1;
        let Some(value) = args.get(i) else {
            return Err(usage.to_string());
        };
        if out.insert(flag.to_string(), value.clone()).is_some() {
            return Err(usage.to_string());
        }
        i += 1;
    }
    Ok(out)
}

pub fn required_path(
    values: &HashMap<String, String>,
    key: &str,
    usage: &str,
) -> Result<PathBuf, String> {
    values
        .get(key)
        .map(PathBuf::from)
        .ok_or_else(|| usage.to_string())
}

pub fn required_string(
    values: &HashMap<String, String>,
    key: &str,
    usage: &str,
) -> Result<String, String> {
    values.get(key).cloned().ok_or_else(|| usage.to_string())
}

pub fn optional_string(values: &HashMap<String, String>, key: &str) -> Option<String> {
    values.get(key).cloned()
}

pub fn has_switch(values: &HashMap<String, String>, key: &str) -> bool {
    values.contains_key(key)
}
