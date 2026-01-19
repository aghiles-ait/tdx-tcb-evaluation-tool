mod utils;

use anyhow::{Context, Result};
use clap::Parser;
use dcap_rs::types::quotes::QeReportCertData;
use dcap_rs::types::quotes::version_4::QuoteV4;
use dcap_rs::utils::cert::{parse_certchain, parse_pem};
use serde_json::Value;
use std::path::PathBuf;
use utils::get_pck_fmspc_and_issuer;
use x509_parser::oid_registry::asn1_rs::{oid, FromDer, Integer, OctetString, Oid, Sequence};
use x509_parser::prelude::*;

#[derive(Parser)]
struct Opt {
    #[clap(long)]
    quote: PathBuf,
}

fn fetch_tcb_info(fmspc: &str) -> Result<Value> {
    let url = format!(
        "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc={}",
        fmspc
    );

    println!("Fetching TCB info from: {}", url);

    let response: Value = ureq::get(&url)
        .call()
        .context("Failed to fetch TCB info from Intel API")?
        .into_json()
        .context("Failed to parse TCB info JSON")?;

    Ok(response)
}

fn main() -> Result<()> {
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

    // Fetch TCB info from Intel API
    println!("\n=== Fetching TCB Info from Intel ===");
    let tcb_info = fetch_tcb_info(&fmspc.to_uppercase())?;

    // Find the UpToDate TCB level
    let tcb_levels = tcb_info["tcbInfo"]["tcbLevels"]
        .as_array()
        .context("tcbLevels not found")?;

    let uptodate_level = tcb_levels
        .iter()
        .find(|level| level["tcbStatus"].as_str() == Some("UpToDate"))
        .context("No UpToDate TCB level found")?;

    let tcb_date = uptodate_level["tcbDate"].as_str().unwrap_or("unknown");

    println!("\n=== TCB Comparison ===");
    println!("UpToDate TCB level (tcbDate: {}):", tcb_date);

    // Extract required values from the UpToDate level
    let required_sgx_tcb: Vec<u8> = uptodate_level["tcb"]["sgxtcbcomponents"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|v| v["svn"].as_u64().unwrap_or(0) as u8)
                .collect()
        })
        .unwrap_or_else(|| vec![0; 16]);

    let required_pcesvn = uptodate_level["tcb"]["pcesvn"].as_u64().unwrap_or(0) as u16;

    let required_tdx_tcb: Vec<u8> = uptodate_level["tcb"]["tdxtcbcomponents"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|v| v["svn"].as_u64().unwrap_or(0) as u8)
                .collect()
        })
        .unwrap_or_else(|| vec![0; 16]);

    println!("  Required SGX TCB Components: {:?}", required_sgx_tcb);
    println!("  Required PCESVN: {}", required_pcesvn);
    println!("  Required TDX TCB Components: {:?}", required_tdx_tcb);

    println!("\nYour values:");
    println!("  SGX TCB Components: {:?}", sgx_tcb_svn);
    println!("  PCESVN: {}", pcesvn);
    println!("  TDX TCB Components: {:?}", tee_tcb_svn);

    // Full TCB comparison
    let mut is_uptodate = true;
    let mut outdated_components: Vec<String> = Vec::new();

    // Check SGX TCB
    for i in 0..16.min(required_sgx_tcb.len()) {
        if sgx_tcb_svn[i] < required_sgx_tcb[i] {
            outdated_components.push(format!(
                "SGX TCB[{}]: {} < {}",
                i, sgx_tcb_svn[i], required_sgx_tcb[i]
            ));
            is_uptodate = false;
        }
    }

    // Check PCESVN
    if pcesvn < required_pcesvn {
        outdated_components.push(format!("PCESVN: {} < {}", pcesvn, required_pcesvn));
        is_uptodate = false;
    }

    // Check TDX TCB
    for i in 0..16.min(required_tdx_tcb.len()) {
        if tee_tcb_svn[i] < required_tdx_tcb[i] {
            outdated_components.push(format!(
                "TDX TCB[{}]: {} < {}",
                i, tee_tcb_svn[i], required_tdx_tcb[i]
            ));
            is_uptodate = false;
        }
    }

    if is_uptodate {
        println!("\n✅ TCB Status: UpToDate");
    } else {
        println!("\n⚠️  TCB Status: OutOfDate");
        println!("Outdated components:");
        for comp in &outdated_components {
            println!("  ❌ {}", comp);
        }
    }

    Ok(())
}

/// Extract SGX TCB (CPUSVN) and PCESVN from PCK certificate's SGX extensions
fn extract_tcb_from_pck(cert: &X509Certificate<'_>) -> ([u8; 16], u16) {
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
            "1.2.840.113741.1.13.1.2" => {
                let (_, tcb_seq) = Sequence::from_der(remaining).unwrap();
                let mut tcb_content = tcb_seq.content.as_ref();

                while !tcb_content.is_empty() {
                    let (rest, comp_seq) = Sequence::from_der(tcb_content).unwrap();
                    tcb_content = rest;

                    let (val_bytes, comp_oid) = Oid::from_der(comp_seq.content.as_ref()).unwrap();
                    let oid_str = comp_oid.to_id_string();

                    if let Some(comp_num_str) = oid_str.strip_prefix("1.2.840.113741.1.13.1.2.")
                        && let Ok(comp_num) = comp_num_str.parse::<usize>()
                    {
                        if let Ok((_, value)) = Integer::from_der(val_bytes) {
                            let val = value.as_u32().unwrap_or(0);
                            if (1..=16).contains(&comp_num) {
                                cpusvn[comp_num - 1] = val as u8;
                            } else if comp_num == 17 {
                                pcesvn = val as u16;
                            }
                        } else if let Ok((_, octet)) = OctetString::from_der(val_bytes) {
                            let bytes = octet.as_ref();
                            if (1..=16).contains(&comp_num) && !bytes.is_empty() {
                                cpusvn[comp_num - 1] = bytes[0];
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
