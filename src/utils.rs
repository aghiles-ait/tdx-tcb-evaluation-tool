use dcap_rs::types::quotes::QeReportCertData;
use dcap_rs::types::quotes::version_4::QuoteV4;
use dcap_rs::utils::cert::{get_x509_issuer_cn, parse_certchain, parse_pem};
use x509_parser::oid_registry::asn1_rs::{oid, FromDer, OctetString, Oid, Sequence};
use x509_parser::prelude::*;

#[derive(Debug)]
pub enum Ca {
    Processor,
    Platform,
}

pub fn get_pck_fmspc_and_issuer(quote: &QuoteV4) -> (String, Ca) {
    let raw_cert_data = QeReportCertData::from_bytes(&quote.signature.qe_cert_data.cert_data);

    let pem = parse_pem(&raw_cert_data.qe_cert_data.cert_data).expect("Failed to parse cert data");
    let cert_chain = parse_certchain(&pem);
    let pck = &cert_chain[0];

    let pck_issuer = get_x509_issuer_cn(pck);

    let pck_ca = match pck_issuer.as_str() {
        "Intel SGX PCK Platform CA" => Ca::Platform,
        "Intel SGX PCK Processor CA" => Ca::Processor,
        _ => panic!("Unknown PCK Issuer"),
    };

    let fmspc_slice = extract_fmspc_from_extension(pck);
    let fmspc = hex::encode(fmspc_slice);

    (fmspc, pck_ca)
}

pub fn extract_fmspc_from_extension(cert: &X509Certificate<'_>) -> [u8; 6] {
    let sgx_extensions_bytes = cert
        .get_extension_unique(&oid!(1.2.840.113741.1.13.1))
        .unwrap()
        .unwrap()
        .value;

    let (_, sgx_extensions) = Sequence::from_der(sgx_extensions_bytes).unwrap();

    let mut fmspc = [0; 6];

    let mut i = sgx_extensions.content.as_ref();

    while !i.is_empty() {
        let (j, current_sequence) = Sequence::from_der(i).unwrap();
        i = j;
        let (j, current_oid) = Oid::from_der(current_sequence.content.as_ref()).unwrap();
        match current_oid.to_id_string().as_str() {
            "1.2.840.113741.1.13.1.4" => {
                let (k, fmspc_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                fmspc.copy_from_slice(fmspc_bytes.as_ref());
                break;
            }
            _ => continue,
        }
    }

    fmspc
}
