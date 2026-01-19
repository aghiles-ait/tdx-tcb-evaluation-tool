# TDX TCB Evaluation Tool

A command-line tool to evaluate the TCB (Trusted Computing Base) status of Intel TDX quotes by comparing them against Intel's official TCB Info.

## Overview

This tool parses a TDX Quote (v4) and:
1. Extracts TCB values from the quote (SGX TCB, PCESVN, TDX TCB)
2. Fetches the latest TCB requirements from Intel's Provisioning Certification Service (PCS)
3. Compares your quote's TCB levels against Intel's "UpToDate" requirements
4. Reports whether your platform is up-to-date or which components are outdated

## Installation

```bash
cargo build --release
```

## Usage

```bash
./target/release/tcb-evaluation-tool --quote <path-to-quote.dat>
```

### Example

```bash
./target/release/tcb-evaluation-tool --quote quote-tdx-phoenix.dat
```

### Sample Output

```
=== TDX Quote Analysis ===

Quote Version: 4
TEE Type: 0x81 (0x00=SGX, 0x81=TDX)
FMSPC: 70A06D070000
PCK Issuer: PLATFORM

=== TCB Values from Quote ===
SGX TCB SVN (from PCK cert): [2, 2, 2, 2, 4, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]
PCESVN (from PCK cert): 13
TDX TCB SVN (from quote body): [4, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
Report Data: 7464782d70686f656e6978...

=== Fetching TCB Info from Intel ===
Fetching TCB info from: https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=70A06D070000

=== TCB Comparison ===
UpToDate TCB level (tcbDate: 2024-11-13T00:00:00Z):
  Required SGX TCB Components: [2, 2, 2, 2, 4, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]
  Required PCESVN: 13
  Required TDX TCB Components: [5, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

Your values:
  SGX TCB Components: [2, 2, 2, 2, 4, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]
  PCESVN: 13
  TDX TCB Components: [4, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

⚠️  TCB Status: OutOfDate
Outdated components:
  ❌ TDX TCB[0]: 4 < 5
```

## TCB Components Explained

### SGX TCB SVN (16 components)
Security Version Numbers for various SGX platform components:
- CPU microcode
- BIOS/firmware
- Platform configuration

### PCESVN
Provisioning Certification Enclave Security Version Number - indicates the security level of the PCE.

### TDX TCB SVN (16 components)
Security Version Numbers for TDX-specific components:
- **TDX TCB[0]**: TDX Module (SEAM) SVN
- **TDX TCB[1]**: TDX Module secondary SVN
- **TDX TCB[2]**: TDX Late Microcode Update SVN

## TCB Status

- **✅ UpToDate**: All TCB components meet or exceed Intel's requirements
- **⚠️ OutOfDate**: One or more components are below required levels (security advisories may apply)

## How TCB Matching Works

For a quote to be "UpToDate", **ALL** of these must be ≥ Intel's requirements:
1. SGX TCB Components (all 16)
2. PCESVN
3. TDX TCB Components (all 16)

## Dependencies

- [dcap-rs](https://github.com/automata-network/dcap-rs) - DCAP quote parsing
- [ureq](https://crates.io/crates/ureq) - HTTP client for Intel API
- [x509-parser](https://crates.io/crates/x509-parser) - PCK certificate parsing

## Data Sources

- **Quote TCB values**: Extracted from the TDX Quote structure and embedded PCK certificate
- **Required TCB levels**: Fetched live from Intel's PCS API:
  ```
  https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc={FMSPC}
  ```

## License

MIT
