mod utils;

use clap::Parser;
use dcap_rs::types::quotes::QeReportCertData;
use dcap_rs::types::quotes::version_4::QuoteV4;
use dcap_rs::utils::cert::{parse_certchain, parse_pem};
use std::path::PathBuf;
use utils::get_pck_fmspc_and_issuer;
use x509_parser::oid_registry::asn1_rs::{FromDer, Integer, OctetString, Oid, Sequence, oid};
use x509_parser::prelude::*;

#[derive(Parser)]
struct Opt {
    #[clap(long)]
    quote: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let quote_bytes = std::fs::read(&opt.quote)?;
    let quote = QuoteV4::from_bytes(&quote_bytes);

    println!("=== TDX Quote Analysis ===\n");

    // Basic info
    println!("Quote Version: {}", quote.header.version);
    println!(
        "TEE Type: 0x{:x} (0x00=SGX, 0x81=TDX)",
        quote.header.tee_type
    );

    // Get FMSPC and parse PCK certificate
    let (fmspc, issuer) = get_pck_fmspc_and_issuer(&quote);
    println!("FMSPC: {}", fmspc.to_uppercase());
    println!("PCK Issuer: {:?}", issuer);

    // Parse PCK certificate for SGX TCB and PCESVN
    let raw_cert_data = QeReportCertData::from_bytes(&quote.signature.qe_cert_data.cert_data);
    let pem = parse_pem(&raw_cert_data.qe_cert_data.cert_data).expect("Failed to parse cert data");
    let cert_chain = parse_certchain(&pem);
    let pck = &cert_chain[0];

    // Extract SGX TCB (CPUSVN) and PCESVN from PCK certificate
    let (sgx_tcb_svn, pcesvn) = extract_tcb_from_pck(pck);

    // Extract TEE TCB SVN from raw bytes (offset 48-64 in quote body for TDX)
    println!("\n=== TCB Values from Quote ===");
    let tee_tcb_svn = &quote_bytes[48..64];

    println!("SGX TCB SVN (from PCK cert): {:?}", sgx_tcb_svn);
    println!("PCESVN (from PCK cert): {}", pcesvn);
    println!("TDX TCB SVN (from quote body): {:?}", tee_tcb_svn);

    // Report Data is at offset 568 in the body (48 + 520 = 568 to 632)
    let report_data = &quote_bytes[568..632];
    println!("Report Data: {}", hex::encode(report_data));

    println!("\n=== TCB Comparison ===");
    println!("To check if your quote is UpToDate, compare against Intel TCB Info:");
    println!(
        "  https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc={}",
        fmspc.to_uppercase()
    );

    // Required values for UpToDate (from Intel TCB Info, tcbDate 2024-11-13)
    let required_sgx_tcb: [u8; 16] = [2, 2, 2, 2, 4, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0];
    let required_pcesvn: u16 = 13;
    let required_tdx_tcb: [u8; 16] = [5, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    println!("\nRequired UpToDate TCB levels (tcbDate 2024-11-13):");
    println!("  SGX TCB Components: {:?}", required_sgx_tcb);
    println!("  PCESVN: {}", required_pcesvn);
    println!("  TDX TCB Components: {:?}", required_tdx_tcb);

    println!("\nYour values:");
    println!("  SGX TCB Components: {:?}", sgx_tcb_svn);
    println!("  PCESVN: {}", pcesvn);
    println!("  TDX TCB Components: {:?}", tee_tcb_svn);

    // Full TCB comparison
    let mut is_uptodate = true;

    // Check SGX TCB
    for i in 0..16 {
        if sgx_tcb_svn[i] < required_sgx_tcb[i] {
            println!(
                "  ❌ SGX TCB[{}] outdated: {} < {}",
                i, sgx_tcb_svn[i], required_sgx_tcb[i]
            );
            is_uptodate = false;
        }
    }

    // Check PCESVN
    if pcesvn < required_pcesvn {
        println!("  ❌ PCESVN outdated: {} < {}", pcesvn, required_pcesvn);
        is_uptodate = false;
    }

    // Check TDX TCB
    for i in 0..16 {
        if tee_tcb_svn[i] < required_tdx_tcb[i] {
            println!(
                "  ❌ TDX TCB[{}] outdated: {} < {}",
                i, tee_tcb_svn[i], required_tdx_tcb[i]
            );
            is_uptodate = false;
        }
    }

    if is_uptodate {
        println!("\n✅ TCB Status: UpToDate");
    } else {
        println!("\n⚠️  TCB Status: OutOfDate");
    }

    Ok(())
}

/// Extract SGX TCB (CPUSVN) and PCESVN from PCK certificate's SGX extensions
fn extract_tcb_from_pck<'a>(cert: &'a X509Certificate<'a>) -> ([u8; 16], u16) {
    let sgx_extensions_bytes = cert
        .get_extension_unique(&oid!(1.2.840.113741.1.13.1))
        .unwrap()
        .unwrap()
        .value;

    let (_, sgx_extensions) = Sequence::from_der(sgx_extensions_bytes).unwrap();

    let mut cpusvn = [0u8; 16];
    let mut pcesvn: u16 = 0;

    let mut i = sgx_extensions.content.as_ref();

    while !i.is_empty() {
        let (j, current_sequence) = Sequence::from_der(i).unwrap();
        i = j;
        let (remaining, current_oid) = Oid::from_der(current_sequence.content.as_ref()).unwrap();

        match current_oid.to_id_string().as_str() {
            // TCB extension (contains CPUSVN components and PCESVN)
            "1.2.840.113741.1.13.1.2" => {
                // Parse the TCB sequence
                let (_, tcb_seq) = Sequence::from_der(remaining).unwrap();
                let mut tcb_content = tcb_seq.content.as_ref();

                // Parse each component (SGX TCB SVN 01-16 and PCESVN at 17)
                while !tcb_content.is_empty() {
                    let (rest, comp_seq) = Sequence::from_der(tcb_content).unwrap();
                    tcb_content = rest;

                    let (val_bytes, comp_oid) = Oid::from_der(comp_seq.content.as_ref()).unwrap();
                    let oid_str = comp_oid.to_id_string();

                    // Extract component number from OID (1.2.840.113741.1.13.1.2.X)
                    if let Some(comp_num_str) = oid_str.strip_prefix("1.2.840.113741.1.13.1.2.") {
                        if let Ok(comp_num) = comp_num_str.parse::<usize>() {
                            // Try to parse as Integer first, fall back to OctetString
                            if let Ok((_, value)) = Integer::from_der(val_bytes) {
                                let val = value.as_u32().unwrap_or(0);

                                if comp_num >= 1 && comp_num <= 16 {
                                    cpusvn[comp_num - 1] = val as u8;
                                } else if comp_num == 17 {
                                    pcesvn = val as u16;
                                }
                            } else if let Ok((_, octet)) = OctetString::from_der(val_bytes) {
                                // Some components might be encoded as OctetString
                                let bytes = octet.as_ref();
                                if comp_num >= 1 && comp_num <= 16 && !bytes.is_empty() {
                                    cpusvn[comp_num - 1] = bytes[0];
                                }
                            }
                        }
                    }
                }
            }
            _ => continue,
        }
    }

    (cpusvn, pcesvn)
}
