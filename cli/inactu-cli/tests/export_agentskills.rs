mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use common::{temp_dir, write};
use serde_json::json;

fn make_index_and_store(base: &Path) -> (std::path::PathBuf, String, std::path::PathBuf) {
    let inactu_home = base.join("inactu-home");
    let digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let store = inactu_home.join("store").join("sha256").join(&digest[7..]);
    fs::create_dir_all(&store).expect("store should be created");

    let manifest = json!({
        "name": "demo.echo",
        "version": "0.1.0",
        "entrypoint": "run",
        "artifact": digest,
        "capabilities": [
            {"kind": "fs.read", "value": "/data/input"},
            {"kind": "net", "value": "https://example.com/api"}
        ],
        "signers": ["alice.dev"]
    });
    write(
        &store.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)
            .expect("manifest should serialize")
            .as_slice(),
    );

    let index = json!({
        "schema_version": "1.0.0",
        "entries": [
            {
                "skill": digest,
                "source": "./skill.tar.zst",
                "store": store,
                "installed_at": 1,
                "manifest_name": "demo.echo",
                "manifest_version": "0.1.0"
            }
        ]
    });
    fs::create_dir_all(&inactu_home).expect("inactu home should be created");
    write(
        &inactu_home.join("index.json"),
        serde_json::to_vec_pretty(&index)
            .expect("index should serialize")
            .as_slice(),
    );

    (inactu_home, digest.to_string(), store)
}

#[test]
fn export_agentskills_codex_repo_writes_expected_layout() {
    let root = temp_dir("export_agentskills_codex_repo");
    let repo = root.join("repo");
    fs::create_dir_all(&repo).expect("repo should be created");
    let (inactu_home, digest, store) = make_index_and_store(&root);

    let output = Command::new(env!("CARGO_BIN_EXE_inactu-cli"))
        .args([
            "export",
            "agentskills",
            "--agent",
            "codex",
            "--scope",
            "repo",
        ])
        .current_dir(&repo)
        .env("INACTU_HOME", &inactu_home)
        .output()
        .expect("export should run");
    assert!(output.status.success(), "{:?}", output);

    let exported_root = repo.join(".agents").join("skills");
    let dirs = fs::read_dir(&exported_root)
        .expect("export root should exist")
        .collect::<Result<Vec<_>, _>>()
        .expect("dirs should be readable");
    assert_eq!(dirs.len(), 1, "expected one exported skill folder");

    let skill_dir = dirs[0].path();
    let skill_md = fs::read_to_string(skill_dir.join("SKILL.md")).expect("SKILL.md should exist");
    assert!(skill_md.contains("name: \"demo.echo\""), "{skill_md}");
    assert!(skill_md.contains(&digest), "{skill_md}");

    let run_sh = fs::read_to_string(skill_dir.join("scripts/run.sh")).expect("run.sh should exist");
    assert!(run_sh.contains("inactu-cli"), "{run_sh}");
    assert!(
        run_sh.contains(store.to_str().expect("store utf8")),
        "{run_sh}"
    );
    assert!(run_sh.contains("--policy"), "{run_sh}");

    let policy = fs::read_to_string(skill_dir.join("references/ide-safe.policy.json"))
        .expect("policy should exist");
    assert!(policy.contains("\"net\": []"), "{policy}");
    assert!(policy.contains("/data/input"), "{policy}");
    assert!(policy.contains("/tmp/inactu-scratch"), "{policy}");
    assert!(policy.contains("alice.dev"), "{policy}");
}

#[test]
fn export_agentskills_claude_user_targets_home_dot_claude() {
    let root = temp_dir("export_agentskills_claude_user");
    let repo = root.join("repo");
    let home = root.join("home");
    fs::create_dir_all(&repo).expect("repo should be created");
    fs::create_dir_all(&home).expect("home should be created");
    let (inactu_home, _digest, _store) = make_index_and_store(&root);

    let output = Command::new(env!("CARGO_BIN_EXE_inactu-cli"))
        .args([
            "export",
            "agentskills",
            "--agent",
            "claude",
            "--scope",
            "user",
        ])
        .current_dir(&repo)
        .env("INACTU_HOME", &inactu_home)
        .env("HOME", &home)
        .output()
        .expect("export should run");
    assert!(output.status.success(), "{:?}", output);

    let exported_root = home.join(".claude").join("skills");
    assert!(
        exported_root.is_dir(),
        "expected {}",
        exported_root.display()
    );
}

#[test]
fn export_agentskills_rejects_admin_scope_for_non_codex() {
    let root = temp_dir("export_agentskills_invalid_scope");
    let repo = root.join("repo");
    fs::create_dir_all(&repo).expect("repo should be created");
    let (inactu_home, _digest, _store) = make_index_and_store(&root);

    let output = Command::new(env!("CARGO_BIN_EXE_inactu-cli"))
        .args([
            "export",
            "agentskills",
            "--agent",
            "claude",
            "--scope",
            "admin",
        ])
        .current_dir(&repo)
        .env("INACTU_HOME", &inactu_home)
        .output()
        .expect("export should run");
    assert!(!output.status.success(), "{:?}", output);

    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("scope=admin is only supported for agent=codex"),
        "{stderr}"
    );
}
