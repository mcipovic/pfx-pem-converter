mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{ec_key, ed25519_key, make_cert, make_pfx, rsa_key};
use openssl::pkey::PKey;
use openssl::symm::Cipher;
use openssl::x509::X509;
use pfx_pem_converter::{
    ConvertError, PemToPfxOptions, PfxToPemOptions, default_pfx_path, pem_file_plan, pem_to_pfx,
    pem_to_pfx_from_text, pfx_to_pem,
};
use tempfile::tempdir;

const LEGACY_PFX: &[u8] = include_bytes!("fixtures/legacy-rc2.pfx");

fn write(path: &Path, bytes: &[u8]) -> PathBuf {
    fs::write(path, bytes).expect("write fixture");
    path.to_path_buf()
}

#[test]
fn pfx_to_pem_rsa_with_chain_orders_leaf_to_root() {
    let root_key = rsa_key();
    let root = make_cert(&root_key, "Root CA", None, true);
    let intermediate_key = rsa_key();
    let intermediate = make_cert(
        &intermediate_key,
        "Intermediate CA",
        Some((&root, &root_key)),
        true,
    );
    let leaf_key = rsa_key();
    let leaf = make_cert(
        &leaf_key,
        "server.example.com",
        Some((&intermediate, &intermediate_key)),
        false,
    );

    // Deliberately shuffle the chain: the converter must order it itself.
    let pfx = make_pfx(
        Some(&leaf_key),
        Some(&leaf),
        &[root.clone(), intermediate.clone()],
        "secret",
    );

    let dir = tempdir().unwrap();
    let input = write(&dir.path().join("server.pfx"), &pfx);
    let output_dir = dir.path().join("out");

    let report = pfx_to_pem(&PfxToPemOptions {
        input,
        password: "secret".to_owned(),
        output_dir: Some(output_dir.clone()),
    })
    .expect("convert");

    assert_eq!(report.outputs.len(), 3);
    assert_eq!(report.certificate_count, 3);
    assert!(report.key_type.as_deref().unwrap().contains("RSA"));
    assert!(report.warnings.is_empty());

    let fullchain = X509::stack_from_pem(
        &fs::read(output_dir.join("server-fullchain.pem")).expect("read fullchain"),
    )
    .expect("parse fullchain");
    let names: Vec<String> = fullchain.iter().map(common::common_name).collect();
    assert_eq!(
        names,
        vec!["server.example.com", "Intermediate CA", "Root CA"]
    );

    let extracted_key =
        PKey::private_key_from_pem(&fs::read(output_dir.join("server-private-key.pem")).unwrap())
            .expect("parse key");
    assert!(extracted_key.public_eq(&leaf.public_key().unwrap()));
}

#[test]
fn pfx_to_pem_ec_key() {
    let key = ec_key();
    let cert = make_cert(&key, "ec.example.com", None, false);
    let pfx = make_pfx(Some(&key), Some(&cert), &[], "secret");

    let dir = tempdir().unwrap();
    let input = write(&dir.path().join("ec.pfx"), &pfx);
    let report = pfx_to_pem(&PfxToPemOptions {
        input,
        password: "secret".to_owned(),
        output_dir: Some(dir.path().join("out")),
    })
    .expect("convert");

    assert_eq!(report.certificate_count, 1);
    assert!(report.key_type.as_deref().unwrap().contains("EC"));
}

#[test]
fn pfx_to_pem_ed25519_key() {
    let key = ed25519_key();
    let cert = make_cert(&key, "ed25519.example.com", None, false);
    let pfx = make_pfx(Some(&key), Some(&cert), &[], "secret");

    let dir = tempdir().unwrap();
    let input = write(&dir.path().join("ed25519.pfx"), &pfx);
    let report = pfx_to_pem(&PfxToPemOptions {
        input,
        password: "secret".to_owned(),
        output_dir: Some(dir.path().join("out")),
    })
    .expect("convert");

    assert_eq!(report.certificate_count, 1);
    assert!(report.key_type.as_deref().unwrap().contains("Ed25519"));
}

#[test]
fn legacy_rc2_pfx_is_supported() {
    let dir = tempdir().unwrap();
    let input = write(&dir.path().join("legacy.pfx"), LEGACY_PFX);

    let report = pfx_to_pem(&PfxToPemOptions {
        input,
        password: "test-password".to_owned(),
        output_dir: Some(dir.path().join("out")),
    })
    .expect("legacy PFX should parse");

    assert_eq!(report.certificate_count, 1);
    assert_eq!(report.outputs.len(), 3);
}

#[test]
fn wrong_password_is_reported_clearly() {
    let key = rsa_key();
    let cert = make_cert(&key, "wrong.example.com", None, false);
    let pfx = make_pfx(Some(&key), Some(&cert), &[], "correct");

    let dir = tempdir().unwrap();
    let input = write(&dir.path().join("wrong.pfx"), &pfx);
    let error = pfx_to_pem(&PfxToPemOptions {
        input,
        password: "incorrect".to_owned(),
        output_dir: Some(dir.path().join("out")),
    })
    .unwrap_err();

    assert!(matches!(error, ConvertError::WrongPassword { .. }));
    assert!(!dir.path().join("out").exists());
}

#[test]
fn empty_password_round_trips() {
    let key = rsa_key();
    let cert = make_cert(&key, "empty-password.example.com", None, false);

    let dir = tempdir().unwrap();
    let key_path = write(
        &dir.path().join("key.pem"),
        &key.private_key_to_pem_pkcs8().unwrap(),
    );
    let cert_path = write(&dir.path().join("cert.pem"), &cert.to_pem().unwrap());

    let report = pem_to_pfx(&PemToPfxOptions {
        key: key_path,
        cert: cert_path,
        chain: None,
        password: String::new(),
        output: Some(dir.path().join("empty.pfx")),
    })
    .expect("create PFX");

    assert!(report.warnings.iter().any(|w| w.contains("empty password")));

    let report = pfx_to_pem(&PfxToPemOptions {
        input: dir.path().join("empty.pfx"),
        password: String::new(),
        output_dir: Some(dir.path().join("out")),
    })
    .expect("read PFX");
    assert_eq!(report.certificate_count, 1);
}

#[test]
fn unicode_password_and_paths() {
    let key = rsa_key();
    let cert = make_cert(&key, "unicode.example.com", None, false);

    let dir = tempdir().unwrap();
    let folder = dir.path().join("sertifikati čšž");
    fs::create_dir_all(&folder).unwrap();

    let key_path = write(
        &folder.join("privatni ključ.pem"),
        &key.private_key_to_pem_pkcs8().unwrap(),
    );
    let cert_path = write(&folder.join("sertifikat čšž.pem"), &cert.to_pem().unwrap());
    let pfx_path = folder.join("moj paket čšž.pfx");
    let password = "lozinka-čšž-€";

    pem_to_pfx(&PemToPfxOptions {
        key: key_path,
        cert: cert_path,
        chain: None,
        password: password.to_owned(),
        output: Some(pfx_path.clone()),
    })
    .expect("create PFX");

    let report = pfx_to_pem(&PfxToPemOptions {
        input: pfx_path,
        password: password.to_owned(),
        output_dir: Some(folder.join("izlaz čšž")),
    })
    .expect("read PFX");

    assert_eq!(report.certificate_count, 1);
    assert_eq!(report.outputs.len(), 3);
}

#[test]
fn certificate_only_pfx_writes_certificates_without_key() {
    let key = rsa_key();
    let cert = make_cert(&key, "cert-only.example.com", None, false);
    let pfx = make_pfx(None, Some(&cert), &[], "secret");

    let dir = tempdir().unwrap();
    let input = write(&dir.path().join("cert-only.pfx"), &pfx);
    let output_dir = dir.path().join("out");
    let report = pfx_to_pem(&PfxToPemOptions {
        input,
        password: "secret".to_owned(),
        output_dir: Some(output_dir.clone()),
    })
    .expect("convert");

    assert_eq!(report.outputs.len(), 2);
    assert!(report.key_type.is_none());
    assert!(report.warnings.iter().any(|w| w.contains("no private key")));
    assert!(!output_dir.join("cert-only-private-key.pem").exists());
    assert!(output_dir.join("cert-only-certificate.pem").exists());
}

#[test]
fn key_only_pfx_writes_only_the_key() {
    let key = rsa_key();
    let pfx = make_pfx(Some(&key), None, &[], "secret");

    let dir = tempdir().unwrap();
    let input = write(&dir.path().join("key-only.pfx"), &pfx);
    let output_dir = dir.path().join("out");
    let report = pfx_to_pem(&PfxToPemOptions {
        input,
        password: "secret".to_owned(),
        output_dir: Some(output_dir.clone()),
    })
    .expect("convert");

    assert_eq!(report.outputs.len(), 1);
    assert_eq!(report.certificate_count, 0);
    assert!(report.warnings.iter().any(|w| w.contains("no certificate")));
    assert!(output_dir.join("key-only-private-key.pem").exists());
}

#[test]
fn mismatched_key_and_certificate_are_rejected() {
    let key = rsa_key();
    let other_key = rsa_key();
    let cert = make_cert(&other_key, "mismatch.example.com", None, false);

    let dir = tempdir().unwrap();
    let key_path = write(
        &dir.path().join("key.pem"),
        &key.private_key_to_pem_pkcs8().unwrap(),
    );
    let cert_path = write(&dir.path().join("cert.pem"), &cert.to_pem().unwrap());
    let pfx_path = dir.path().join("mismatch.pfx");

    let error = pem_to_pfx(&PemToPfxOptions {
        key: key_path,
        cert: cert_path,
        chain: None,
        password: "secret".to_owned(),
        output: Some(pfx_path.clone()),
    })
    .unwrap_err();

    assert!(matches!(error, ConvertError::KeyMismatch));
    assert!(!pfx_path.exists());
}

#[test]
fn encrypted_private_keys_are_rejected_with_a_clear_error() {
    let key = rsa_key();
    let cert = make_cert(&key, "encrypted.example.com", None, false);
    let encrypted = key
        .private_key_to_pem_pkcs8_passphrase(Cipher::aes_128_cbc(), b"key-password")
        .unwrap();

    let dir = tempdir().unwrap();
    let key_path = write(&dir.path().join("key.pem"), &encrypted);
    let cert_path = write(&dir.path().join("cert.pem"), &cert.to_pem().unwrap());

    let error = pem_to_pfx(&PemToPfxOptions {
        key: key_path,
        cert: cert_path,
        chain: None,
        password: "secret".to_owned(),
        output: Some(dir.path().join("out.pfx")),
    })
    .unwrap_err();

    assert!(matches!(error, ConvertError::EncryptedKey { .. }));
}

#[test]
fn existing_outputs_are_never_overwritten() {
    let key = rsa_key();
    let cert = make_cert(&key, "overwrite.example.com", None, false);
    let pfx = make_pfx(Some(&key), Some(&cert), &[], "secret");

    let dir = tempdir().unwrap();
    let input = write(&dir.path().join("overwrite.pfx"), &pfx);
    let output_dir = dir.path().join("out");

    pfx_to_pem(&PfxToPemOptions {
        input: input.clone(),
        password: "secret".to_owned(),
        output_dir: Some(output_dir.clone()),
    })
    .expect("first convert");

    let certificate_path = output_dir.join("overwrite-certificate.pem");
    let original = fs::read(&certificate_path).unwrap();

    let error = pfx_to_pem(&PfxToPemOptions {
        input,
        password: "secret".to_owned(),
        output_dir: Some(output_dir.clone()),
    })
    .unwrap_err();

    assert!(matches!(error, ConvertError::OutputExists(_)));
    assert_eq!(fs::read(certificate_path).unwrap(), original);
}

#[test]
fn a_collision_does_not_leave_a_partial_output_set() {
    let key = rsa_key();
    let cert = make_cert(&key, "partial.example.com", None, false);
    let pfx = make_pfx(Some(&key), Some(&cert), &[], "secret");

    let dir = tempdir().unwrap();
    let input = write(&dir.path().join("partial.pfx"), &pfx);
    let output_dir = dir.path().join("out");
    fs::create_dir_all(&output_dir).unwrap();
    fs::write(output_dir.join("partial-certificate.pem"), b"already here").unwrap();

    let error = pfx_to_pem(&PfxToPemOptions {
        input,
        password: "secret".to_owned(),
        output_dir: Some(output_dir.clone()),
    })
    .unwrap_err();

    assert!(matches!(error, ConvertError::OutputExists(_)));
    assert!(!output_dir.join("partial-private-key.pem").exists());
    assert!(!output_dir.join("partial-fullchain.pem").exists());
}

#[test]
fn new_pfx_uses_legacy_compatible_3des_encryption() {
    let key = rsa_key();
    let cert = make_cert(&key, "compat.example.com", None, false);

    let dir = tempdir().unwrap();
    let key_path = write(
        &dir.path().join("key.pem"),
        &key.private_key_to_pem_pkcs8().unwrap(),
    );
    let cert_path = write(&dir.path().join("cert.pem"), &cert.to_pem().unwrap());
    let pfx_path = dir.path().join("compat.pfx");

    pem_to_pfx(&PemToPfxOptions {
        key: key_path,
        cert: cert_path,
        chain: None,
        password: "secret".to_owned(),
        output: Some(pfx_path.clone()),
    })
    .expect("create PFX");

    let der = fs::read(&pfx_path).unwrap();
    // pbeWithSHA1And3-KeyTripleDES-CBC (1.2.840.113549.1.12.1.3)
    let triple_des_oid = [
        0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x03,
    ];
    let aes_256_oid = [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A,
    ];

    assert!(
        der.windows(triple_des_oid.len())
            .any(|window| window == triple_des_oid)
    );
    assert!(
        !der.windows(aes_256_oid.len())
            .any(|window| window == aes_256_oid)
    );

    // And OpenSSL must be able to read it back.
    pfx_to_pem(&PfxToPemOptions {
        input: pfx_path,
        password: "secret".to_owned(),
        output_dir: Some(dir.path().join("out")),
    })
    .expect("parse created PFX");
}

#[test]
fn duplicate_leaf_in_chain_is_removed() {
    let root_key = rsa_key();
    let root = make_cert(&root_key, "Duplicate Root", None, true);
    let intermediate_key = rsa_key();
    let intermediate = make_cert(
        &intermediate_key,
        "Duplicate Intermediate",
        Some((&root, &root_key)),
        true,
    );
    let leaf_key = rsa_key();
    let leaf = make_cert(
        &leaf_key,
        "duplicate.example.com",
        Some((&intermediate, &intermediate_key)),
        false,
    );

    let dir = tempdir().unwrap();
    let key_path = write(
        &dir.path().join("key.pem"),
        &leaf_key.private_key_to_pem_pkcs8().unwrap(),
    );

    let mut cert_pem = leaf.to_pem().unwrap();
    cert_pem.extend(intermediate.to_pem().unwrap());
    let cert_path = write(&dir.path().join("cert.pem"), &cert_pem);

    let mut chain_pem = leaf.to_pem().unwrap();
    chain_pem.extend(root.to_pem().unwrap());
    let chain_path = write(&dir.path().join("chain.pem"), &chain_pem);

    let pfx_path = dir.path().join("dedup.pfx");
    let report = pem_to_pfx(&PemToPfxOptions {
        key: key_path,
        cert: cert_path,
        chain: Some(chain_path),
        password: "secret".to_owned(),
        output: Some(pfx_path.clone()),
    })
    .expect("create PFX");

    assert_eq!(report.certificate_count, 3);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("duplicate"))
    );

    let out_dir = dir.path().join("out");
    let extracted = pfx_to_pem(&PfxToPemOptions {
        input: pfx_path,
        password: "secret".to_owned(),
        output_dir: Some(out_dir.clone()),
    })
    .expect("read PFX");

    assert_eq!(extracted.certificate_count, 3);
    let fullchain =
        X509::stack_from_pem(&fs::read(out_dir.join("dedup-fullchain.pem")).unwrap()).unwrap();
    assert_eq!(fullchain.len(), 3);
}

#[test]
fn der_certificate_input_is_accepted() {
    let key = rsa_key();
    let cert = make_cert(&key, "der.example.com", None, false);

    let dir = tempdir().unwrap();
    let key_path = write(
        &dir.path().join("key.pem"),
        &key.private_key_to_pem_pkcs8().unwrap(),
    );
    let cert_path = write(&dir.path().join("cert.der"), &cert.to_der().unwrap());

    pem_to_pfx(&PemToPfxOptions {
        key: key_path,
        cert: cert_path,
        chain: None,
        password: "secret".to_owned(),
        output: Some(dir.path().join("der.pfx")),
    })
    .expect("DER certificate should work");
}

#[test]
fn output_folder_defaults_to_the_input_folder() {
    let key = rsa_key();
    let cert = make_cert(&key, "default-folder.example.com", None, false);
    let pfx = make_pfx(Some(&key), Some(&cert), &[], "secret");

    let dir = tempdir().unwrap();
    let input = write(&dir.path().join("default-folder.pfx"), &pfx);

    let report = pfx_to_pem(&PfxToPemOptions {
        input,
        password: "secret".to_owned(),
        output_dir: None,
    })
    .expect("convert");

    assert_eq!(report.output_dir, dir.path());
    assert!(dir.path().join("default-folder-private-key.pem").exists());
}

#[test]
fn default_paths_are_sanitized() {
    let out = Path::new("out");
    let plan = pem_file_plan(Path::new("my cert.pfx"), Some(out));
    assert_eq!(plan.base, "my cert");
    assert_eq!(plan.private_key, out.join("my cert-private-key.pem"));
    assert_eq!(plan.fullchain, out.join("my cert-fullchain.pem"));

    let pfx = default_pfx_path(Path::new("my cert.crt"));
    assert_eq!(
        pfx.file_name().unwrap().to_string_lossy().as_ref(),
        "my cert.pfx"
    );

    let reserved = pem_file_plan(Path::new("CON.pfx"), Some(out));
    assert_eq!(reserved.base, "_CON");

    let invalid = pem_file_plan(Path::new("a<b>c|d?.pfx"), Some(out));
    assert_eq!(invalid.base, "a_b_c_d_");
}

#[test]
fn invalid_inputs_return_specific_errors() {
    let dir = tempdir().unwrap();

    let corrupt = write(&dir.path().join("corrupt.pfx"), b"this is not a PFX");
    let error = pfx_to_pem(&PfxToPemOptions {
        input: corrupt,
        password: String::new(),
        output_dir: Some(dir.path().join("out")),
    })
    .unwrap_err();
    assert!(matches!(error, ConvertError::InvalidPfx { .. }));

    let bad_key = write(&dir.path().join("bad-key.pem"), b"not a key");
    let good_key = rsa_key();
    let cert = make_cert(&good_key, "bad.example.com", None, false);
    let cert_path = write(&dir.path().join("cert.pem"), &cert.to_pem().unwrap());
    let error = pem_to_pfx(&PemToPfxOptions {
        key: bad_key,
        cert: cert_path.clone(),
        chain: None,
        password: "secret".to_owned(),
        output: Some(dir.path().join("bad.pfx")),
    })
    .unwrap_err();
    assert!(matches!(error, ConvertError::InvalidKey { .. }));

    let good_key_path = write(
        &dir.path().join("key.pem"),
        &good_key.private_key_to_pem_pkcs8().unwrap(),
    );
    let bad_cert = write(&dir.path().join("bad-cert.pem"), b"not a certificate");
    let error = pem_to_pfx(&PemToPfxOptions {
        key: good_key_path,
        cert: bad_cert,
        chain: None,
        password: "secret".to_owned(),
        output: Some(dir.path().join("bad-cert.pfx")),
    })
    .unwrap_err();
    assert!(matches!(error, ConvertError::InvalidCertificate { .. }));
}

#[test]
fn nul_in_password_is_rejected() {
    let dir = tempdir().unwrap();
    let error = pfx_to_pem(&PfxToPemOptions {
        input: dir.path().join("anything.pfx"),
        password: "a\0b".to_owned(),
        output_dir: Some(dir.path().join("out")),
    })
    .unwrap_err();
    assert!(matches!(error, ConvertError::NulInPassword));
}

#[cfg(unix)]
#[test]
fn output_permissions_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let key = rsa_key();
    let cert = make_cert(&key, "perms.example.com", None, false);
    let pfx = make_pfx(Some(&key), Some(&cert), &[], "secret");

    let dir = tempdir().unwrap();
    let input = write(&dir.path().join("perms.pfx"), &pfx);
    let output_dir = dir.path().join("out");

    pfx_to_pem(&PfxToPemOptions {
        input,
        password: "secret".to_owned(),
        output_dir: Some(output_dir.clone()),
    })
    .expect("convert");

    for file in [
        "perms-private-key.pem",
        "perms-certificate.pem",
        "perms-fullchain.pem",
    ] {
        let mode = fs::metadata(output_dir.join(file))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{file} should be private");
    }
}

#[test]
fn pasted_pem_text_creates_a_valid_pfx() {
    let key = rsa_key();
    let cert = make_cert(&key, "pasted.example.com", None, false);
    let key_pem = String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let cert_pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();

    let dir = tempdir().unwrap();
    let pfx_path = dir.path().join("pasted.pfx");
    let report = pem_to_pfx_from_text(&key_pem, &cert_pem, None, "secret", pfx_path.clone())
        .expect("create PFX from pasted text");

    assert_eq!(report.certificate_count, 1);
    assert_eq!(report.outputs, vec![pfx_path.clone()]);

    let extracted = pfx_to_pem(&PfxToPemOptions {
        input: pfx_path,
        password: "secret".to_owned(),
        output_dir: Some(dir.path().join("out")),
    })
    .expect("read PFX made from pasted text");
    assert_eq!(extracted.certificate_count, 1);
}

#[test]
fn pasted_pem_text_accepts_a_chain() {
    let root_key = rsa_key();
    let root = make_cert(&root_key, "Pasted Root", None, true);
    let intermediate_key = rsa_key();
    let intermediate = make_cert(
        &intermediate_key,
        "Pasted Intermediate",
        Some((&root, &root_key)),
        true,
    );
    let leaf_key = rsa_key();
    let leaf = make_cert(
        &leaf_key,
        "pasted-chain.example.com",
        Some((&intermediate, &intermediate_key)),
        false,
    );

    let key_pem = String::from_utf8(leaf_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let cert_pem = String::from_utf8(leaf.to_pem().unwrap()).unwrap();
    let mut chain_pem = String::from_utf8(intermediate.to_pem().unwrap()).unwrap();
    chain_pem.push_str(&String::from_utf8(root.to_pem().unwrap()).unwrap());

    let dir = tempdir().unwrap();
    let pfx_path = dir.path().join("pasted-chain.pfx");
    let report = pem_to_pfx_from_text(
        &key_pem,
        &cert_pem,
        Some(&chain_pem),
        "secret",
        pfx_path.clone(),
    )
    .expect("create PFX with pasted chain");

    assert_eq!(report.certificate_count, 3);

    let out_dir = dir.path().join("out");
    let extracted = pfx_to_pem(&PfxToPemOptions {
        input: pfx_path,
        password: "secret".to_owned(),
        output_dir: Some(out_dir.clone()),
    })
    .expect("read PFX");

    assert_eq!(extracted.certificate_count, 3);
    let fullchain =
        X509::stack_from_pem(&fs::read(out_dir.join("pasted-chain-fullchain.pem")).unwrap())
            .unwrap();
    let names: Vec<String> = fullchain.iter().map(common::common_name).collect();
    assert_eq!(
        names,
        vec![
            "pasted-chain.example.com",
            "Pasted Intermediate",
            "Pasted Root"
        ]
    );
}
