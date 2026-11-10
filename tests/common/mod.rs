use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509, X509NameBuilder};

pub fn rsa_key() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).expect("RSA key")).expect("PKey")
}

pub fn ec_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256 group");
    PKey::from_ec_key(EcKey::generate(&group).expect("EC key")).expect("PKey")
}

pub fn ed25519_key() -> PKey<Private> {
    PKey::generate_ed25519().expect("Ed25519 key")
}

pub fn make_cert(
    key: &PKey<Private>,
    common_name: &str,
    issuer: Option<(&X509, &PKey<Private>)>,
    is_ca: bool,
) -> X509 {
    let mut builder = X509::builder().expect("X509 builder");
    builder.set_version(2).expect("version");

    let mut serial = BigNum::new().expect("bignum");
    serial
        .rand(128, MsbOption::MAYBE_ZERO, false)
        .expect("serial");
    let serial = serial.to_asn1_integer().expect("serial integer");
    builder.set_serial_number(&serial).expect("set serial");

    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .expect("CN");
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "PFX PEM Tests")
        .expect("O");
    let name = name.build();
    builder.set_subject_name(&name).expect("subject");

    if let Some((issuer_cert, _)) = issuer {
        builder
            .set_issuer_name(issuer_cert.subject_name())
            .expect("issuer");
    } else {
        builder.set_issuer_name(&name).expect("issuer");
    }

    builder.set_pubkey(key).expect("public key");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("not before"))
        .expect("set not before");
    builder
        .set_not_after(&Asn1Time::days_from_now(3650).expect("not after"))
        .expect("set not after");
    let mut basic_constraints = BasicConstraints::new();
    basic_constraints.critical();
    if is_ca {
        basic_constraints.ca();
    }
    builder
        .append_extension(basic_constraints.build().expect("basic constraints"))
        .expect("append basic constraints");

    if is_ca {
        let usage = KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .expect("CA key usage");
        builder.append_extension(usage).expect("append key usage");
    } else {
        let usage = KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()
            .expect("leaf key usage");
        builder.append_extension(usage).expect("append key usage");
    }

    if let Some((_, issuer_key)) = issuer {
        builder
            .sign(issuer_key, MessageDigest::sha256())
            .expect("sign");
    } else if key.id() == openssl::pkey::Id::ED25519 {
        builder
            .sign(key, MessageDigest::null())
            .expect("self-sign Ed25519");
    } else {
        builder
            .sign(key, MessageDigest::sha256())
            .expect("self-sign");
    }

    builder.build()
}

pub fn make_pfx(
    key: Option<&PKey<Private>>,
    cert: Option<&X509>,
    chain: &[X509],
    password: &str,
) -> Vec<u8> {
    let mut builder = Pkcs12::builder();
    builder.name("PFX PEM Tests");

    if let Some(key) = key {
        builder.pkey(key);
    }
    if let Some(cert) = cert {
        builder.cert(cert);
    }
    if !chain.is_empty() {
        let mut stack = Stack::new().expect("stack");
        for item in chain {
            stack.push(item.clone()).expect("push chain");
        }
        builder.ca(stack);
    }

    builder
        .build2(password)
        .expect("build PFX")
        .to_der()
        .expect("PFX DER")
}

pub fn common_name(cert: &X509) -> String {
    cert.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .expect("CN")
        .data()
        .to_string()
        .expect("CN text")
}
