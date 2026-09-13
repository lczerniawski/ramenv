use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ramenv"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn root_help_and_version_are_available_without_a_workspace() {
    let help = run(&["--help"]);
    assert!(help.status.success());
    assert!(stdout(&help).contains("Secure Environment Variable Manager"));
    assert!(stdout(&help).contains("Usage: ramenv <COMMAND>"));

    let version = run(&["--version"]);
    assert!(version.status.success());
    assert_eq!(stdout(&version).trim(), "ramenv 0.1.0");
}

#[test]
fn every_subcommand_exposes_help_without_touching_the_filesystem() {
    for command in [
        "init",
        "onboard",
        "create-env",
        "remove-env",
        "set",
        "delete",
        "list",
        "validate",
        "diff",
        "run",
        "rotate",
    ] {
        let output = run(&[command, "--help"]);
        assert!(
            output.status.success(),
            "{command} --help failed: {}",
            stderr(&output)
        );
        assert!(
            stdout(&output).contains("Usage:"),
            "missing usage for {command}"
        );
    }
}

#[test]
fn unknown_commands_and_missing_required_arguments_exit_with_usage_error() {
    for args in [
        vec!["unknown"],
        vec!["create-env"],
        vec!["remove-env"],
        vec!["set", "development"],
        vec!["delete", "development"],
        vec!["list"],
        vec!["diff", "development"],
        vec!["run"],
        vec!["rotate"],
    ] {
        let output = run(&args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "unexpected status for {args:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("Usage:"),
            "missing usage for {args:?}"
        );
    }
}

#[test]
fn boolean_flags_reject_values_and_unexpected_arguments() {
    for args in [
        vec!["list", "development", "--reveal=true"],
        vec!["set", "development", "KEY", "--plaintext=true"],
        vec!["validate", "one", "two"],
        vec!["rotate", "development", "extra"],
    ] {
        let output = run(&args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "accepted invalid args {args:?}"
        );
    }
}
