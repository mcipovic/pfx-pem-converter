//! Headless self-test used by CI and by `pfx-pem --self-test`.
//!
//! The fixture is a throwaway RSA certificate protected with an old RC2-based
//! PKCS#12 encryption. A successful run proves that the bundled OpenSSL,
//! including its legacy provider, is usable in the packaged binary.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use openssl::pkey::PKey;
use openssl::x509::X509;

use pfx_pem_converter::{PemToPfxOptions, PfxToPemOptions, pem_to_pfx, pfx_to_pem};

const FIXTURE_PFX: &[u8] = include_bytes!("../tests/fixtures/legacy-rc2.pfx");
const PASSWORD: &str = "test-password";

pub fn run() -> Result<(), String> {
    let dir = temporary_directory()?;
    let result = run_in(&dir);
    let _ = fs::remove_dir_all(&dir);
    result
}

fn run_in(dir: &Path) -> Result<(), String> {
    let input = dir.join("input.pfx");
    fs::write(&input, FIXTURE_PFX)
        .map_err(|error| format!("could not write the fixture: {error}"))?;

    let pem_dir = dir.join("pem output");
    let report = pfx_to_pem(&PfxToPemOptions {
        input: input.clone(),
        password: PASSWORD.to_owned(),
        output_dir: Some(pem_dir.clone()),
    })
    .map_err(|error| format!("PFX to PEM failed: {error}"))?;

    if report.outputs.len() != 3 {
        return Err(format!(
            "expected 3 PEM files, got {}",
            report.outputs.len()
        ));
    }

    let key_path = pem_dir.join("input-private-key.pem");
    let cert_path = pem_dir.join("input-certificate.pem");
    let chain_path = pem_dir.join("input-fullchain.pem");

    for path in [&key_path, &cert_path, &chain_path] {
        if !path.is_file() {
            return Err(format!("missing output file: {}", path.display()));
        }
    }

    let key_bytes =
        fs::read(&key_path).map_err(|error| format!("could not read the PEM key: {error}"))?;
    let key = PKey::private_key_from_pem(&key_bytes)
        .map_err(|error| format!("extracted key is not a PEM private key: {error}"))?;

    let cert_bytes =
        fs::read(&cert_path).map_err(|error| format!("could not read the PEM cert: {error}"))?;
    let cert = X509::from_pem(&cert_bytes)
        .map_err(|error| format!("extracted certificate is invalid: {error}"))?;

    let public_key = cert
        .public_key()
        .map_err(|error| format!("certificate has no public key: {error}"))?;
    if !key.public_eq(&public_key) {
        return Err("extracted key does not match the extracted certificate".to_owned());
    }

    let roundtrip = dir.join("roundtrip.pfx");
    pem_to_pfx(&PemToPfxOptions {
        key: key_path,
        cert: cert_path,
        chain: Some(chain_path),
        password: PASSWORD.to_owned(),
        output: Some(roundtrip.clone()),
    })
    .map_err(|error| format!("PEM to PFX failed: {error}"))?;

    let check_dir = dir.join("roundtrip-pem");
    pfx_to_pem(&PfxToPemOptions {
        input: roundtrip,
        password: PASSWORD.to_owned(),
        output_dir: Some(check_dir),
    })
    .map_err(|error| format!("round-trip PFX to PEM failed: {error}"))?;

    Ok(())
}

fn temporary_directory() -> Result<PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("pfx-pem-selftest-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir)
        .map_err(|error| format!("could not create a temporary folder: {error}"))?;
    Ok(dir)
}
