//! Core conversion logic for the PFX ↔ PEM converter.
//!
//! The public functions are deliberately small: read the inputs, convert in
//! memory, then write the outputs. Nothing is written unless the whole
//! conversion succeeded, and existing files are never overwritten.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{Id, PKey, Private};
use openssl::provider::Provider;
use openssl::stack::Stack;
use openssl::x509::X509;
use thiserror::Error;

const PRIVATE_KEY_SUFFIX: &str = "-private-key.pem";
const CERTIFICATE_SUFFIX: &str = "-certificate.pem";
const FULLCHAIN_SUFFIX: &str = "-fullchain.pem";

/// PFX → PEM options.
#[derive(Debug, Clone)]
pub struct PfxToPemOptions {
    /// The `.pfx` / `.p12` file to read.
    pub input: PathBuf,
    /// The PFX password. An empty password is valid.
    pub password: String,
    /// Where to write the PEM files. Defaults to the input file's folder.
    pub output_dir: Option<PathBuf>,
}

/// PEM → PFX options.
#[derive(Debug, Clone)]
pub struct PemToPfxOptions {
    /// The unencrypted PEM private key.
    pub key: PathBuf,
    /// The PEM (or DER) leaf certificate.
    pub cert: PathBuf,
    /// Optional PEM (or DER) intermediate/root certificates.
    pub chain: Option<PathBuf>,
    /// The password that will protect the new PFX. An empty password is valid.
    pub password: String,
    /// The output PFX path. Defaults to `<certificate name>.pfx`.
    pub output: Option<PathBuf>,
}

/// What a successful conversion produced.
#[derive(Debug, Clone)]
pub struct ConversionReport {
    /// Files that were written, in display order.
    pub outputs: Vec<PathBuf>,
    /// Non-fatal notes for the user.
    pub warnings: Vec<String>,
    /// Number of certificates extracted (PFX → PEM) or embedded (PEM → PFX).
    pub certificate_count: usize,
    /// Private key algorithm, if a key was involved.
    pub key_type: Option<String>,
    /// Folder containing the outputs.
    pub output_dir: PathBuf,
}

/// The PEM filenames planned for a PFX → PEM conversion.
#[derive(Debug, Clone)]
pub struct PemFilePlan {
    pub base: String,
    pub private_key: PathBuf,
    pub certificate: PathBuf,
    pub fullchain: PathBuf,
}

/// Conversion errors. All messages are safe to show directly in the UI.
#[derive(Debug, Error)]
pub enum ConvertError {
    #[error("Could not read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("Could not write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("Output already exists: {0}")]
    OutputExists(PathBuf),

    #[error("Could not create the output folder {path}: {source}")]
    OutputDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("The output path is not a folder: {0}")]
    NotAFolder(PathBuf),

    #[error("The output folder does not exist: {0}")]
    MissingFolder(PathBuf),

    #[error("The password is incorrect or the PFX file is damaged.")]
    WrongPassword { detail: String },

    #[error("This is not a valid PFX/PKCS#12 file.")]
    InvalidPfx { detail: String },

    #[error("The PFX uses an encryption algorithm that is not supported on this build.")]
    UnsupportedPfx { detail: String },

    #[error("The PFX contains no certificate and no private key.")]
    EmptyPfx,

    #[error(
        "The private key could not be read. Use an unencrypted PEM key (PKCS#8, PKCS#1 or SEC1)."
    )]
    InvalidKey { detail: String },

    #[error("The private key is encrypted. Decrypt it first, then try again.")]
    EncryptedKey { detail: String },

    #[error("The certificate could not be read. Use a PEM or DER certificate.")]
    InvalidCertificate { detail: String },

    #[error("The certificate chain could not be read. Use PEM or DER certificates.")]
    InvalidChain { detail: String },

    #[error("The private key does not match the certificate.")]
    KeyMismatch,

    #[error("The password contains an unsupported NUL character.")]
    NulInPassword,

    #[error("OpenSSL could not be initialized: {0}")]
    OpenSslInit(String),

    #[error("OpenSSL could not create the PFX file.")]
    CreatePfx { detail: String },

    #[error("Internal conversion error: {0}")]
    Internal(String),
}

impl ConvertError {
    /// Extra technical text for a collapsible "details" section.
    pub fn detail(&self) -> Option<String> {
        match self {
            Self::Read { source, .. } | Self::Write { source, .. } => Some(source.to_string()),
            Self::OutputDir { source, .. } => Some(source.to_string()),
            Self::WrongPassword { detail }
            | Self::InvalidPfx { detail }
            | Self::UnsupportedPfx { detail }
            | Self::InvalidKey { detail }
            | Self::EncryptedKey { detail }
            | Self::InvalidCertificate { detail }
            | Self::InvalidChain { detail }
            | Self::CreatePfx { detail } => Some(detail.clone()),
            Self::OpenSslInit(detail) | Self::Internal(detail) => Some(detail.clone()),
            Self::OutputExists(_)
            | Self::NotAFolder(_)
            | Self::MissingFolder(_)
            | Self::EmptyPfx
            | Self::KeyMismatch
            | Self::NulInPassword => None,
        }
    }
}

struct Providers {
    _default: Provider,
    _legacy: Option<Provider>,
}

static PROVIDERS: OnceLock<Result<Providers, String>> = OnceLock::new();

/// Loads OpenSSL's default and legacy providers exactly once.
///
/// The legacy provider is required to read older PFX files that use RC2. It is
/// best-effort: modern PFX files still work when it is unavailable.
pub fn init() -> Result<(), ConvertError> {
    let result = PROVIDERS.get_or_init(|| {
        // Loading any provider disables OpenSSL's fallback loading, so the
        // default provider must be loaded explicitly and kept alive first.
        let default = Provider::load(None, "default").map_err(|e| ssl_errors(&e))?;
        let legacy = Provider::load(None, "legacy").ok();
        Ok(Providers {
            _default: default,
            _legacy: legacy,
        })
    });

    match result {
        Ok(_) => Ok(()),
        Err(detail) => Err(ConvertError::OpenSslInit(detail.clone())),
    }
}

/// Converts a PFX/PKCS#12 file into a private key, a leaf certificate and a
/// full chain PEM file.
pub fn pfx_to_pem(options: &PfxToPemOptions) -> Result<ConversionReport, ConvertError> {
    init()?;

    if options.password.contains('\0') {
        return Err(ConvertError::NulInPassword);
    }

    let bytes = read_file(&options.input)?;
    let parsed = parse_pfx(&bytes, &options.password)?;

    let mut warnings = Vec::new();
    let key = parsed.pkey;
    let mut leaf = parsed.cert;
    let mut chain: Vec<X509> = match parsed.ca {
        Some(stack) => stack.into_iter().collect(),
        None => Vec::new(),
    };

    if leaf.is_none() && !chain.is_empty() {
        leaf = Some(chain.remove(0));
        warnings.push(
            "The PFX did not mark a leaf certificate; the first certificate in the bundle was used."
                .to_owned(),
        );
    }

    if key.is_none() && leaf.is_none() {
        return Err(ConvertError::EmptyPfx);
    }

    if key.is_none() {
        warnings.push(
            "The PFX contains no private key. Only the certificate files were written.".to_owned(),
        );
    }
    if leaf.is_none() {
        warnings
            .push("The PFX contains no certificate. Only the private key was written.".to_owned());
    }

    let out_dir = options
        .output_dir
        .clone()
        .unwrap_or_else(|| parent_or_cwd(&options.input));
    prepare_output_dir(&out_dir)?;

    let plan = pem_file_plan(&options.input, Some(&out_dir));

    // Serialize everything before touching the filesystem.
    let key_pem = match &key {
        Some(key) => Some(
            key.private_key_to_pem_pkcs8()
                .map_err(|e| ConvertError::Internal(ssl_errors(&e)))?,
        ),
        None => None,
    };

    let ordered_chain = match &leaf {
        Some(leaf) => order_chain(leaf.clone(), chain)?,
        None => Vec::new(),
    };

    let leaf_pem = match ordered_chain.first() {
        Some(leaf) => Some(
            leaf.to_pem()
                .map_err(|e| ConvertError::Internal(ssl_errors(&e)))?,
        ),
        None => None,
    };

    let mut fullchain_pem = Vec::new();
    for cert in &ordered_chain {
        fullchain_pem.extend(
            cert.to_pem()
                .map_err(|e| ConvertError::Internal(ssl_errors(&e)))?,
        );
    }

    let mut files: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    if let Some(pem) = key_pem {
        files.push((plan.private_key.clone(), pem));
    }
    if let Some(pem) = leaf_pem {
        files.push((plan.certificate.clone(), pem));
        files.push((plan.fullchain.clone(), fullchain_pem));
    }

    // Refuse to overwrite anything. Check first so a collision cannot leave a
    // partial set of files behind.
    for (path, _) in &files {
        if path.exists() {
            return Err(ConvertError::OutputExists(path.clone()));
        }
    }

    let written = write_all_new(&files)?;

    Ok(ConversionReport {
        outputs: written,
        warnings,
        certificate_count: ordered_chain.len(),
        key_type: key.as_ref().map(key_type_name),
        output_dir: out_dir,
    })
}

/// Converts an unencrypted PEM private key plus a certificate and optional
/// chain into a password-protected PFX file.
///
/// The PFX uses 3DES/SHA-1 encryption because that is the format Windows and
/// older Java keystores import most reliably.
pub fn pem_to_pfx(options: &PemToPfxOptions) -> Result<ConversionReport, ConvertError> {
    init()?;

    if options.password.contains('\0') {
        return Err(ConvertError::NulInPassword);
    }

    let key = parse_key(&read_file(&options.key)?)?;
    let cert_bytes = read_file(&options.cert)?;
    let mut certs = parse_certificates(&cert_bytes, CertKind::Leaf)?;

    if certs.is_empty() {
        return Err(ConvertError::InvalidCertificate {
            detail: "The certificate file contains no certificates.".to_owned(),
        });
    }

    let leaf = certs.remove(0);
    let leaf_public_key = leaf
        .public_key()
        .map_err(|e| ConvertError::InvalidCertificate {
            detail: ssl_errors(&e),
        })?;

    if !key.public_eq(&leaf_public_key) {
        return Err(ConvertError::KeyMismatch);
    }

    let mut warnings = Vec::new();
    if !certs.is_empty() {
        warnings.push(format!(
            "The certificate file contained {} extra certificate(s); they were added to the chain.",
            certs.len()
        ));
    }

    let mut chain = certs;

    if let Some(chain_path) = &options.chain {
        let chain_bytes = read_file(chain_path)?;
        let extra = parse_certificates(&chain_bytes, CertKind::Chain)?;
        chain.extend(extra);
    }

    let leaf_der = leaf
        .to_der()
        .map_err(|e| ConvertError::Internal(ssl_errors(&e)))?;
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    seen.insert(leaf_der.clone());

    let mut deduped_chain = Vec::with_capacity(chain.len());
    let mut removed_leaf = false;
    for cert in chain {
        let der = cert
            .to_der()
            .map_err(|e| ConvertError::Internal(ssl_errors(&e)))?;
        if !seen.insert(der.clone()) {
            if der == leaf_der {
                removed_leaf = true;
            }
            continue;
        }
        deduped_chain.push(cert);
    }

    if removed_leaf {
        warnings.push(
            "The leaf certificate was also present in the chain; the duplicate was removed."
                .to_owned(),
        );
    }

    if options.password.is_empty() {
        warnings.push("The PFX was created with an empty password.".to_owned());
    }

    let output = options
        .output
        .clone()
        .unwrap_or_else(|| default_pfx_path(&options.cert));

    if output.exists() {
        return Err(ConvertError::OutputExists(output));
    }

    let output_dir = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| parent_or_cwd(&output));

    if !output_dir.is_dir() {
        return Err(ConvertError::MissingFolder(output_dir));
    }

    let mut ca = Stack::new().map_err(|e| ConvertError::Internal(ssl_errors(&e)))?;
    for cert in &deduped_chain {
        ca.push(cert.clone())
            .map_err(|e| ConvertError::Internal(ssl_errors(&e)))?;
    }
    let has_chain = !deduped_chain.is_empty();

    let friendly_name = friendly_name(&leaf, &output);

    let mut builder = Pkcs12::builder();
    builder
        .name(&friendly_name)
        .pkey(&key)
        .cert(&leaf)
        .key_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
        .cert_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
        .mac_md(MessageDigest::sha1());

    if has_chain {
        builder.ca(ca);
    }

    let pfx = builder
        .build2(&options.password)
        .map_err(|e| ConvertError::CreatePfx {
            detail: ssl_errors(&e),
        })?;
    let der = pfx.to_der().map_err(|e| ConvertError::CreatePfx {
        detail: ssl_errors(&e),
    })?;

    write_new(&output, &der).map_err(|source| {
        if source.kind() == io::ErrorKind::AlreadyExists {
            ConvertError::OutputExists(output.clone())
        } else {
            ConvertError::Write {
                path: output.clone(),
                source,
            }
        }
    })?;

    Ok(ConversionReport {
        outputs: vec![output],
        warnings,
        certificate_count: 1 + deduped_chain.len(),
        key_type: Some(key_type_name(&key)),
        output_dir,
    })
}

/// Returns the PEM filenames that would be used for a PFX → PEM conversion.
pub fn pem_file_plan(input: &Path, output_dir: Option<&Path>) -> PemFilePlan {
    let dir = output_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| parent_or_cwd(input));
    let base = sanitize_base(input);

    PemFilePlan {
        private_key: dir.join(format!("{base}{PRIVATE_KEY_SUFFIX}")),
        certificate: dir.join(format!("{base}{CERTIFICATE_SUFFIX}")),
        fullchain: dir.join(format!("{base}{FULLCHAIN_SUFFIX}")),
        base,
    }
}

/// Returns the default PFX output path for a certificate file.
pub fn default_pfx_path(cert: &Path) -> PathBuf {
    parent_or_cwd(cert).join(format!("{}.pfx", sanitize_base(cert)))
}

fn parse_pfx(
    bytes: &[u8],
    password: &str,
) -> Result<openssl::pkcs12::ParsedPkcs12_2, ConvertError> {
    let pfx = Pkcs12::from_der(bytes).map_err(|e| ConvertError::InvalidPfx {
        detail: ssl_errors(&e),
    })?;

    pfx.parse2(password).map_err(|e| {
        let detail = ssl_errors(&e);
        let reasons: Vec<String> = e
            .errors()
            .iter()
            .filter_map(|error| error.reason().map(ToOwned::to_owned))
            .collect();

        if reasons.iter().any(|reason| reason == "mac verify failure") {
            ConvertError::WrongPassword { detail }
        } else if reasons.iter().any(|reason| reason == "unsupported") {
            ConvertError::UnsupportedPfx { detail }
        } else {
            ConvertError::InvalidPfx { detail }
        }
    })
}

fn parse_key(bytes: &[u8]) -> Result<PKey<Private>, ConvertError> {
    let text = String::from_utf8_lossy(bytes);
    if text.contains("BEGIN ENCRYPTED PRIVATE KEY")
        || (text.contains("Proc-Type: 4,ENCRYPTED") && text.contains("PRIVATE KEY"))
    {
        return Err(ConvertError::EncryptedKey {
            detail: "The PEM file contains an encrypted private key.".to_owned(),
        });
    }

    match PKey::private_key_from_pem(bytes) {
        Ok(key) => Ok(key),
        Err(pem_error) => PKey::private_key_from_der(bytes).map_err(|_| ConvertError::InvalidKey {
            detail: ssl_errors(&pem_error),
        }),
    }
}

enum CertKind {
    Leaf,
    Chain,
}

impl CertKind {
    fn error(&self, detail: String) -> ConvertError {
        match self {
            Self::Leaf => ConvertError::InvalidCertificate { detail },
            Self::Chain => ConvertError::InvalidChain { detail },
        }
    }
}

fn parse_certificates(bytes: &[u8], kind: CertKind) -> Result<Vec<X509>, ConvertError> {
    match X509::stack_from_pem(bytes) {
        Ok(certs) if !certs.is_empty() => Ok(certs),
        Ok(_) => X509::from_der(bytes)
            .map(|cert| vec![cert])
            .map_err(|e| kind.error(ssl_errors(&e))),
        Err(pem_error) => match X509::from_der(bytes) {
            Ok(cert) => Ok(vec![cert]),
            Err(_) => Err(kind.error(ssl_errors(&pem_error))),
        },
    }
}

/// Orders certificates as leaf → intermediates → root using their issuer and
/// subject names, and removes duplicates.
fn order_chain(leaf: X509, chain: Vec<X509>) -> Result<Vec<X509>, ConvertError> {
    let mut ordered = vec![leaf];
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    seen.insert(
        ordered[0]
            .to_der()
            .map_err(|e| ConvertError::Internal(ssl_errors(&e)))?,
    );

    let mut rest = Vec::new();
    for cert in chain {
        let der = cert
            .to_der()
            .map_err(|e| ConvertError::Internal(ssl_errors(&e)))?;
        if seen.insert(der) {
            rest.push(cert);
        }
    }

    loop {
        if ordered.is_empty() {
            break;
        }

        let next = {
            let last = &ordered[ordered.len() - 1];
            let mut found = None;
            for (index, candidate) in rest.iter().enumerate() {
                let is_issuer = candidate
                    .subject_name()
                    .try_cmp(last.issuer_name())
                    .map_err(|e| ConvertError::Internal(ssl_errors(&e)))?
                    == Ordering::Equal;
                if is_issuer {
                    found = Some(index);
                    break;
                }
            }
            found
        };

        match next {
            Some(index) => ordered.push(rest.remove(index)),
            None => break,
        }
    }

    ordered.extend(rest);
    Ok(ordered)
}

fn key_type_name(key: &PKey<Private>) -> String {
    let id = key.id();
    if id == Id::RSA {
        "RSA".to_owned()
    } else if id == Id::RSA_PSS {
        "RSA-PSS".to_owned()
    } else if id == Id::EC {
        "EC".to_owned()
    } else if id == Id::ED25519 {
        "Ed25519".to_owned()
    } else if id == Id::ED448 {
        "Ed448".to_owned()
    } else if id == Id::DSA {
        "DSA".to_owned()
    } else {
        format!("key type {}", id.as_raw())
    }
}

fn friendly_name(cert: &X509, output: &Path) -> String {
    let common_name = cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|entry| entry.data().to_string().ok());

    let fallback = output
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| "certificate".to_owned());

    let raw = common_name
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(fallback);

    let cleaned: String = raw.chars().filter(|ch| *ch != '\0').take(64).collect();
    let cleaned = cleaned.trim().to_owned();

    if cleaned.is_empty() {
        "certificate".to_owned()
    } else {
        cleaned
    }
}

fn sanitize_base(path: &Path) -> String {
    let raw = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    sanitize_component(&raw)
}

fn sanitize_component(raw: &str) -> String {
    let mut cleaned = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
            cleaned.push('_');
        } else {
            cleaned.push(ch);
        }
    }

    let mut cleaned = cleaned.trim().trim_end_matches('.').trim().to_owned();
    if cleaned.is_empty() {
        return "certificate".to_owned();
    }

    cleaned = cleaned.chars().take(80).collect();

    let reserved = matches!(
        cleaned.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    );

    if reserved {
        format!("_{cleaned}")
    } else {
        cleaned
    }
}

fn prepare_output_dir(dir: &Path) -> Result<(), ConvertError> {
    if dir.exists() {
        if dir.is_dir() {
            Ok(())
        } else {
            Err(ConvertError::NotAFolder(dir.to_path_buf()))
        }
    } else {
        fs::create_dir_all(dir).map_err(|source| ConvertError::OutputDir {
            path: dir.to_path_buf(),
            source,
        })
    }
}

fn write_all_new(files: &[(PathBuf, Vec<u8>)]) -> Result<Vec<PathBuf>, ConvertError> {
    let mut written = Vec::with_capacity(files.len());

    for (path, bytes) in files {
        if let Err(source) = write_new(path, bytes) {
            for created in &written {
                let _ = fs::remove_file(created);
            }

            return Err(if source.kind() == io::ErrorKind::AlreadyExists {
                ConvertError::OutputExists(path.clone())
            } else {
                ConvertError::Write {
                    path: path.clone(),
                    source,
                }
            });
        }
        written.push(path.clone());
    }

    Ok(written)
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_file(path: &Path) -> Result<Vec<u8>, ConvertError> {
    fs::read(path).map_err(|source| ConvertError::Read {
        path: path.to_path_buf(),
        source,
    })
}

fn parent_or_cwd(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    }
}

fn ssl_errors(errors: &ErrorStack) -> String {
    errors
        .errors()
        .iter()
        .map(|error| {
            let library = error.library().unwrap_or("unknown library");
            let function = error.function().unwrap_or("unknown function");
            let reason = error.reason().unwrap_or("unknown reason");
            format!("{library} / {function}: {reason}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}
