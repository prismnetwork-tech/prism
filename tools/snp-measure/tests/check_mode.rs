//! `check` is what keeps the reference file honest between builds: every
//! measurement it claims to have computed has to be the one its recorded inputs
//! still produce.

use std::path::{Path, PathBuf};
use std::process::Command;

use prism_snp_measure::reference::ReferenceFile;

const GUEST_ARTIFACTS: &str = "node/guest/out";
const CMDLINE: &str = "console=ttyS0 root=/dev/dm-0 ro";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

fn reference_path() -> PathBuf {
    repo_root().join("crates/attestation/reference/snp-launch-measurements.json")
}

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "snp-measure-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

/// A reference file over the firmware fixture, with the measurement filled in
/// by the tool itself, so the fixture starts out consistent and each test
/// breaks exactly one thing.
fn consistent_reference(scratch: &Path) -> (PathBuf, PathBuf) {
    let artifacts = scratch.join("artifacts");
    std::fs::create_dir_all(&artifacts).unwrap();
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ovmf_AmdSev_suffix.bin");
    std::fs::copy(&fixture, artifacts.join("OVMF.fd")).unwrap();
    std::fs::write(
        artifacts.join("vmlinuz"),
        b"not a kernel, but a measured one",
    )
    .unwrap();
    std::fs::write(artifacts.join("cmdline"), CMDLINE).unwrap();

    let entry = Command::new(env!("CARGO_BIN_EXE_snp-measure"))
        .args([
            "measure",
            "--firmware",
            artifacts.join("OVMF.fd").to_str().unwrap(),
            "--kernel",
            artifacts.join("vmlinuz").to_str().unwrap(),
            "--cmdline",
            CMDLINE,
            "--vcpus",
            "4",
            "--cpu-family",
            "25",
            "--cpu-model",
            "17",
            "--cpu-stepping",
            "1",
            "--image-version",
            "fixture-guest",
        ])
        .output()
        .expect("run snp-measure");
    assert!(
        entry.status.success(),
        "{}",
        String::from_utf8_lossy(&entry.stderr)
    );

    let reference = scratch.join("snp-launch-measurements.json");
    std::fs::write(
        &reference,
        format!(
            "{{\n  \"schema_version\": 1,\n  \"provenance\": \"computed\",\n  \"note\": \"fixture\",\n  \"measurements\": [{}]\n}}\n",
            String::from_utf8(entry.stdout).unwrap()
        ),
    )
    .unwrap();
    (reference, artifacts)
}

fn check(reference: &Path, artifacts: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_snp-measure"))
        .args([
            "check",
            "--reference",
            reference.to_str().unwrap(),
            "--artifacts",
            artifacts.to_str().unwrap(),
        ])
        .output()
        .expect("run snp-measure")
}

fn rewrite(path: &Path, from: &str, to: &str) {
    let contents = std::fs::read_to_string(path).unwrap();
    assert!(
        contents.contains(from),
        "{from} is not in {}",
        path.display()
    );
    std::fs::write(path, contents.replace(from, to)).unwrap();
}

fn flip_first_hex_digit(digest: &str) -> String {
    let flipped = match digest.starts_with('0') {
        true => '1',
        false => '0',
    };
    format!("{flipped}{}", &digest[1..])
}

#[test]
fn a_consistent_reference_file_checks_out() {
    let scratch = scratch("consistent");
    let (reference, artifacts) = consistent_reference(&scratch);

    let output = check(&reference, &artifacts);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("fixture-guest"),
        "check reported nothing"
    );
    std::fs::remove_dir_all(scratch).unwrap();
}

/// An input digest that no longer describes the file is the case that matters
/// most: it is what a swapped kernel or firmware looks like from here.
#[test]
fn an_edited_input_digest_fails_the_check() {
    let scratch = scratch("input-digest");
    let (reference, artifacts) = consistent_reference(&scratch);
    let recorded = ReferenceFile::load(&reference).unwrap().measurements[0]
        .inputs
        .kernel
        .clone();
    let digest = recorded.strip_prefix("sha256:").unwrap();
    rewrite(&reference, digest, &flip_first_hex_digit(digest));

    let output = check(&reference, &artifacts);
    assert!(!output.status.success());
    let complaint = String::from_utf8_lossy(&output.stderr);
    assert!(complaint.contains("vmlinuz"), "{complaint}");
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn an_edited_measurement_fails_the_check() {
    let scratch = scratch("measurement");
    let (reference, artifacts) = consistent_reference(&scratch);
    let recorded = ReferenceFile::load(&reference).unwrap().measurements[0]
        .sha384
        .clone();
    rewrite(&reference, &recorded, &flip_first_hex_digit(&recorded));

    let output = check(&reference, &artifacts);
    assert!(!output.status.success());
    let complaint = String::from_utf8_lossy(&output.stderr);
    assert!(complaint.contains("fixture-guest"), "{complaint}");
    std::fs::remove_dir_all(scratch).unwrap();
}

/// Changing the machine shape changes the measurement, so an entry that keeps
/// its old value after a shape change is caught here rather than by a node that
/// mysteriously stops verifying.
#[test]
fn an_edited_vcpu_count_fails_the_check() {
    let scratch = scratch("vcpus");
    let (reference, artifacts) = consistent_reference(&scratch);
    rewrite(&reference, "\"vcpu_count\": 4", "\"vcpu_count\": 8");

    let output = check(&reference, &artifacts);
    assert!(!output.status.success());
    std::fs::remove_dir_all(scratch).unwrap();
}

/// An edited command line is the interesting version of a missing artifact: the
/// verity root hash lives in there, so a change nobody recorded is a different
/// guest filesystem.
#[test]
fn an_edited_command_line_fails_the_check() {
    let scratch = scratch("cmdline");
    let (reference, artifacts) = consistent_reference(&scratch);
    std::fs::write(artifacts.join("cmdline"), format!("{CMDLINE} quiet")).unwrap();

    let output = check(&reference, &artifacts);
    assert!(!output.status.success());
    let complaint = String::from_utf8_lossy(&output.stderr);
    assert!(complaint.contains("cmdline"), "{complaint}");
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn a_missing_artifact_fails_the_check() {
    let scratch = scratch("missing");
    let (reference, artifacts) = consistent_reference(&scratch);
    std::fs::remove_file(artifacts.join("vmlinuz")).unwrap();

    let output = check(&reference, &artifacts);
    assert!(!output.status.success());
    let complaint = String::from_utf8_lossy(&output.stderr);
    assert!(complaint.contains("vmlinuz"), "{complaint}");
    std::fs::remove_dir_all(scratch).unwrap();
}

/// The gate that runs on every build. While the file says its measurements are
/// placeholders there is nothing to recompute; the moment it says they were
/// computed, this stays red until the inputs that produced them are where the
/// build can hash them. A measurement nobody can recompute is a measurement
/// nobody checked.
#[test]
fn the_checked_in_reference_file_is_what_its_inputs_produce() {
    let file = ReferenceFile::load(&reference_path()).expect("reference file");
    file.check(&repo_root().join(GUEST_ARTIFACTS))
        .expect("every computed reference measurement recomputes from its recorded inputs");
}
