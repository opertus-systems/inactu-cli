use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::constants::MAX_JSON_BYTES;
use crate::fileio::{read_file_limited, write_file};

#[derive(Debug, Clone, Copy)]
pub enum Agent {
    Claude,
    Codex,
    Cursor,
}

#[derive(Debug, Clone, Copy)]
pub enum Scope {
    User,
    Repo,
    Admin,
}

#[derive(Debug, Deserialize)]
struct InstallIndex {
    entries: Vec<InstallIndexEntry>,
}

#[derive(Debug, Deserialize)]
struct InstallIndexEntry {
    skill: String,
    store: String,
}

#[derive(Debug, Deserialize)]
struct ManifestStub {
    name: String,
    version: String,
    entrypoint: String,
    capabilities: Vec<CapabilityStub>,
    signers: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CapabilityStub {
    kind: String,
    value: String,
}

pub struct ExportRequest {
    pub agent: Agent,
    pub scope: Scope,
}

pub fn export_agentskills(request: ExportRequest) -> Result<String, String> {
    validate_scope_for_agent(request.agent, request.scope)?;

    let inactu_home = resolve_inactu_home()?;
    let index_path = inactu_home.join("index.json");
    if !index_path.exists() {
        return Err(format!(
            "no installed skills index at {}; run install first",
            index_path.display()
        ));
    }

    let index_raw = read_file_limited(&index_path, MAX_JSON_BYTES, "index.json")?;
    let index: InstallIndex =
        serde_json::from_slice(&index_raw).map_err(|e| format!("index.json parse failed: {e}"))?;
    if index.entries.is_empty() {
        return Err("no installed skills found in index.json".to_string());
    }

    let target_root = resolve_target_root(request.agent, request.scope)?;
    fs::create_dir_all(&target_root).map_err(|e| {
        format!(
            "failed to create export root {}: {e}",
            target_root.display()
        )
    })?;

    let mut exported_count = 0u64;
    for entry in &index.entries {
        let store = PathBuf::from(&entry.store);
        let manifest_path = store.join("manifest.json");
        let manifest_raw = read_file_limited(&manifest_path, MAX_JSON_BYTES, "manifest.json")?;
        let manifest: ManifestStub = serde_json::from_slice(&manifest_raw)
            .map_err(|e| format!("manifest parse failed ({}): {e}", manifest_path.display()))?;

        let skill_dir_name = skill_dir_name(&manifest.name, &entry.skill);
        let skill_dir = target_root.join(skill_dir_name);
        write_skill_export(&skill_dir, &entry.skill, &store, &manifest)?;
        exported_count += 1;
    }

    Ok(format!(
        "OK export agentskills agent={} scope={} target={} skills={} profile=ide-safe",
        request.agent.as_str(),
        request.scope.as_str(),
        target_root.display(),
        exported_count
    ))
}

fn write_skill_export(
    skill_dir: &Path,
    skill_digest: &str,
    store_dir: &Path,
    manifest: &ManifestStub,
) -> Result<(), String> {
    fs::create_dir_all(skill_dir.join("scripts"))
        .map_err(|e| format!("failed to create scripts dir {}: {e}", skill_dir.display()))?;
    fs::create_dir_all(skill_dir.join("references")).map_err(|e| {
        format!(
            "failed to create references dir {}: {e}",
            skill_dir.display()
        )
    })?;

    let policy_rel = "../references/ide-safe.policy.json";
    let skill_md = render_skill_md(manifest, skill_digest);
    write_file(&skill_dir.join("SKILL.md"), skill_md.as_bytes())?;

    let run_sh = render_run_sh(store_dir, policy_rel, skill_digest);
    let run_sh_path = skill_dir.join("scripts").join("run.sh");
    write_file(&run_sh_path, run_sh.as_bytes())?;
    set_executable_if_unix(&run_sh_path)?;

    let run_ps1 = render_run_ps1(store_dir, policy_rel, skill_digest);
    write_file(
        &skill_dir.join("scripts").join("run.ps1"),
        run_ps1.as_bytes(),
    )?;

    let policy = render_ide_safe_policy(manifest);
    write_file(
        &skill_dir.join("references").join("ide-safe.policy.json"),
        policy.as_bytes(),
    )?;

    let references = render_references_readme(manifest, skill_digest);
    write_file(
        &skill_dir.join("references").join("README.md"),
        references.as_bytes(),
    )?;

    Ok(())
}

fn render_skill_md(manifest: &ManifestStub, skill_digest: &str) -> String {
    format!(
        "---\nname: {}\ndescription: Run '{}' via Inactu verification and ide-safe policy.\n---\n\nUse this skill when you need deterministic execution of `{}` and want capability enforcement with auditable receipts.\n\n## Boundaries\n- Do not run ad-hoc shell commands for this skill.\n- Always use the generated wrappers in `scripts/`.\n- Keep execution inside Inactu policy enforcement and receipt generation.\n\n## Run\n- macOS/Linux: `./scripts/run.sh <input.json> [receipt.json]`\n- Windows: `./scripts/run.ps1 <input.json> [receipt.json]`\n\n## Notes\n- Skill digest: `{}`\n- Manifest version: `{}`\n- Entrypoint: `{}`\n",
        yaml_quote(&manifest.name),
        manifest.name,
        manifest.name,
        skill_digest,
        manifest.version,
        manifest.entrypoint
    )
}

fn render_run_sh(store_dir: &Path, policy_rel: &str, skill_digest: &str) -> String {
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\n\nif [ \"${{#}}\" -lt 1 ] || [ \"${{#}}\" -gt 2 ]; then\n  echo \"usage: $0 <input.json> [receipt.json]\" >&2\n  exit 64\nfi\n\nif [ -z \"${{INACTU_KEYS:-}}\" ] || [ -z \"${{INACTU_KEYS_DIGEST:-}}\" ]; then\n  echo \"set INACTU_KEYS and INACTU_KEYS_DIGEST before running this wrapper\" >&2\n  exit 64\nfi\n\nINPUT=\"$1\"\nRECEIPT=\"${{2:-./receipt.json}}\"\nSCRIPT_DIR=\"$(cd \"$(dirname \"${{BASH_SOURCE[0]}}\")\" && pwd)\"\nPOLICY=\"$SCRIPT_DIR/{}\"\nBUNDLE=\"{}\"\nINACTU_BIN=\"${{INACTU_BIN:-inactu-cli}}\"\n\n\"$INACTU_BIN\" run \\\n  --bundle \"$BUNDLE\" \\\n  --keys \"$INACTU_KEYS\" \\\n  --keys-digest \"$INACTU_KEYS_DIGEST\" \\\n  --policy \"$POLICY\" \\\n  --input \"$INPUT\" \\\n  --receipt \"$RECEIPT\"\n",
        policy_rel,
        store_dir.display()
    )
    + &format!("# exported-skill={}\n", skill_digest)
}

fn render_run_ps1(store_dir: &Path, policy_rel: &str, skill_digest: &str) -> String {
    format!(
        "param(\n  [Parameter(Mandatory=$true)][string]$InputPath,\n  [Parameter(Mandatory=$false)][string]$ReceiptPath = \"./receipt.json\"\n)\n\nif ([string]::IsNullOrEmpty($env:INACTU_KEYS) -or [string]::IsNullOrEmpty($env:INACTU_KEYS_DIGEST)) {{\n  Write-Error \"set INACTU_KEYS and INACTU_KEYS_DIGEST before running this wrapper\"\n  exit 64\n}}\n\n$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path\n$PolicyPath = Join-Path $ScriptDir \"{}\"\n$BundlePath = \"{}\"\n$InactuBin = if ([string]::IsNullOrEmpty($env:INACTU_BIN)) {{ \"inactu-cli\" }} else {{ $env:INACTU_BIN }}\n\n& $InactuBin run `\n  --bundle $BundlePath `\n  --keys $env:INACTU_KEYS `\n  --keys-digest $env:INACTU_KEYS_DIGEST `\n  --policy $PolicyPath `\n  --input $InputPath `\n  --receipt $ReceiptPath\n\n# exported-skill={}\n",
        policy_rel.replace('/', "\\"),
        store_dir.display(),
        skill_digest
    )
}

fn render_ide_safe_policy(manifest: &ManifestStub) -> String {
    let mut fs_read = manifest
        .capabilities
        .iter()
        .filter(|cap| cap.kind == "fs.read" && cap.value.starts_with('/'))
        .map(|cap| cap.value.clone())
        .collect::<Vec<_>>();
    fs_read.sort();
    fs_read.dedup();

    let policy = serde_json::json!({
        "version": 1,
        "trusted_signers": &manifest.signers,
        "capability_ceiling": {
            "fs": serde_json::json!({
                "read": fs_read,
                "write": ["/tmp/inactu-scratch"]
            }),
            "net": [],
            "env": [],
            "exec": false,
            "time": false
        }
    });
    serde_json::to_string_pretty(&policy).unwrap_or_else(|_| "{}".to_string())
}

fn render_references_readme(manifest: &ManifestStub, skill_digest: &str) -> String {
    let mut caps = manifest
        .capabilities
        .iter()
        .map(|cap| format!("- `{}`: `{}`", cap.kind, cap.value))
        .collect::<Vec<_>>();
    caps.sort();
    let cap_lines = if caps.is_empty() {
        "- none".to_string()
    } else {
        caps.join("\n")
    };
    format!(
        "# {} reference\n\n- skill digest: `{}`\n- manifest version: `{}`\n- entrypoint: `{}`\n\n## Declared capabilities\n{}\n\n## ide-safe profile\n- network denied by default (`net: []`)\n- filesystem write restricted to `/tmp/inactu-scratch`\n- `exec` denied\n- `time` denied\n- trusted signers pinned to `manifest.signers`\n",
        manifest.name, skill_digest, manifest.version, manifest.entrypoint, cap_lines
    )
}

fn skill_dir_name(name: &str, skill_digest: &str) -> String {
    let mut slug = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        slug = "skill".to_string();
    }
    let suffix = skill_digest
        .strip_prefix("sha256:")
        .unwrap_or(skill_digest)
        .chars()
        .take(12)
        .collect::<String>();
    format!("{slug}-{suffix}")
}

fn yaml_quote(raw: &str) -> String {
    format!("\"{}\"", raw.replace('"', "\\\""))
}

fn validate_scope_for_agent(agent: Agent, scope: Scope) -> Result<(), String> {
    match (agent, scope) {
        (Agent::Claude, Scope::Admin) => {
            Err("scope=admin is only supported for agent=codex".to_string())
        }
        (Agent::Cursor, Scope::Admin) => {
            Err("scope=admin is only supported for agent=codex".to_string())
        }
        _ => Ok(()),
    }
}

fn resolve_target_root(agent: Agent, scope: Scope) -> Result<PathBuf, String> {
    let home = resolve_home_dir()?;
    let cwd = env::current_dir().map_err(|e| format!("failed to resolve current dir: {e}"))?;
    let root = match (agent, scope) {
        (Agent::Claude, Scope::User) => home.join(".claude").join("skills"),
        (Agent::Claude, Scope::Repo) => cwd.join(".claude").join("skills"),
        (Agent::Codex, Scope::User) => home.join(".agents").join("skills"),
        (Agent::Codex, Scope::Repo) => cwd.join(".agents").join("skills"),
        (Agent::Codex, Scope::Admin) => PathBuf::from("/etc/codex/skills"),
        (Agent::Cursor, Scope::User) => home.join(".cursor").join("skills"),
        (Agent::Cursor, Scope::Repo) => cwd.join(".cursor").join("skills"),
        (_, Scope::Admin) => {
            return Err("scope=admin is only supported for agent=codex".to_string());
        }
    };
    Ok(root)
}

fn resolve_inactu_home() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("INACTU_HOME") {
        return Ok(PathBuf::from(path));
    }
    Ok(resolve_home_dir()?.join(".inactu"))
}

fn resolve_home_dir() -> Result<PathBuf, String> {
    let Some(home) = env::var_os("HOME") else {
        return Err("could not resolve home directory; set HOME".to_string());
    };
    Ok(PathBuf::from(home))
}

impl Agent {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "claude" => Ok(Self::Claude),
            "codex" => Ok(Self::Codex),
            "cursor" => Ok(Self::Cursor),
            _ => Err("unsupported --agent; expected claude, codex, or cursor".to_string()),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
        }
    }
}

impl Scope {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "user" => Ok(Self::User),
            "repo" => Ok(Self::Repo),
            "admin" => Ok(Self::Admin),
            _ => Err("unsupported --scope; expected user, repo, or admin".to_string()),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Repo => "repo",
            Self::Admin => "admin",
        }
    }
}

#[cfg(unix)]
fn set_executable_if_unix(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)
        .map_err(|e| format!("failed to set executable bit on {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn set_executable_if_unix(_path: &Path) -> Result<(), String> {
    Ok(())
}
