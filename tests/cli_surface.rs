use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn help_exposes_doctor_deployment_mint_calldata_and_wallet_generation() {
    Command::cargo_bin("opensea-mint")
        .expect("binary")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: opensea-mint <COMMAND>"))
        .stdout(predicate::str::contains("opensea-mint.exe").not())
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("deploy-executor"))
        .stdout(predicate::str::contains("mint"))
        .stdout(predicate::str::contains("calldata"))
        .stdout(predicate::str::contains("wallets"))
        .stdout(predicate::str::contains("protocol-probe").not())
        .stdout(predicate::str::contains("--config").not())
        .stdout(predicate::str::contains("jobs").not());

    Command::cargo_bin("opensea-mint")
        .expect("binary")
        .args(["mint", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--fund"))
        .stdout(predicate::str::contains("--withdraw"))
        .stdout(predicate::str::contains("--undelegate"))
        .stdout(predicate::str::contains("--stage-index").not())
        .stdout(predicate::str::contains("--broadcast").not())
        .stdout(predicate::str::contains("--wallet").not());

    Command::cargo_bin("opensea-mint")
        .expect("binary")
        .args(["mint", "--fund", "0.01", "--withdraw"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));

    Command::cargo_bin("opensea-mint")
        .expect("binary")
        .args(["calldata", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--collection"))
        .stdout(predicate::str::contains("--wallets"))
        .stdout(predicate::str::contains("--token-id"))
        .stdout(predicate::str::contains("--payer").not())
        .stdout(predicate::str::contains("--broadcast").not());

    Command::cargo_bin("opensea-mint")
        .expect("binary")
        .args(["deploy-executor", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("configured RPC chain"))
        .stdout(predicate::str::contains("--broadcast").not())
        .stdout(predicate::str::contains("--private-key").not());
}

#[test]
fn installed_command_name_exposes_the_package_version() {
    Command::cargo_bin("opensea-mint")
        .expect("binary")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::eq(format!(
            "opensea-mint {}\n",
            env!("CARGO_PKG_VERSION")
        )));
}

#[test]
fn wallet_generator_works_without_env_and_refuses_overwrite() {
    let directory = tempdir().expect("temp directory");
    let output = directory.path().join("generated.json");
    Command::cargo_bin("opensea-mint")
        .expect("binary")
        .current_dir(directory.path())
        .args([
            "wallets",
            "create",
            "--count",
            "2",
            "--output",
            output.to_str().expect("path"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created 2 wallet(s)"));

    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&output).expect("generated manifest"))
            .expect("manifest JSON");
    assert_eq!(manifest["version"], 1);
    assert_eq!(manifest["wallets"].as_array().expect("wallets").len(), 2);
    assert!(
        manifest["wallets"]
            .as_array()
            .expect("wallets")
            .iter()
            .all(|wallet| wallet["quantity"] == 1)
    );

    Command::cargo_bin("opensea-mint")
        .expect("binary")
        .current_dir(directory.path())
        .args([
            "wallets",
            "create",
            "--output",
            output.to_str().expect("path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn mint_fails_before_terminal_or_network_access_when_env_file_is_missing() {
    let directory = tempdir().expect("temp directory");
    Command::cargo_bin("opensea-mint")
        .expect("binary")
        .current_dir(directory.path())
        .arg("mint")
        .assert()
        .failure()
        .stderr(predicate::str::contains("no .env file was found"));
}
