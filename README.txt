# Secure Voting System in C++

The analysis reveals a sophisticated academic implementation of a secure electronic voting system utilizing advanced cryptographic techniques, though the current documentation lacks comprehensiveness and professional presentation standards expected for such a security-critical application.

## Project Overview

This repository implements a **cryptographically secure electronic voting system** written in C++ that demonstrates state-of-the-art privacy-preserving technologies. The system employs **homomorphic encryption** via Microsoft SEAL, **secret sharing** through Shamir's scheme, and modern cryptographic protocols to ensure vote privacy, integrity, and verifiability while maintaining a complete audit trail.

### Key Security Features

**Privacy Protection**: The system utilizes Microsoft SEAL's homomorphic encryption library to perform computations on encrypted votes without revealing individual ballot contents. This ensures that votes remain confidential throughout the entire process, from casting to tallying, addressing fundamental privacy requirements identified in modern voting system guidelines.

**Vote Integrity**: Implementation of Shamir's Secret Sharing scheme distributes trust among multiple trustees, preventing single points of failure and ensuring that vote decryption requires cooperation among authorized parties. This distributed approach aligns with best practices for secure voting systems that require threshold-based security mechanisms.

**Cryptographic Security**: Integration with OpenSSL provides robust cryptographic primitives for secure communications and data protection. The system implements authenticated encryption and secure key management protocols essential for maintaining the integrity of the electoral process.

**Audit Trail**: The system maintains comprehensive logging through file-based storage mechanisms, enabling post-election verification and audit procedures that are increasingly required by modern election security standards.

## System Architecture and Workflow

The voting system follows a **four-phase electoral process** designed to separate concerns and maintain security throughout each stage:

### Phase 1: Election Setup (Admin Module)

The administrative component initializes election parameters including candidate registration, voter enrollment, and trustee configuration. Administrators define the number of candidates, authorized voters, and voting weights while establishing the cryptographic parameters necessary for secure operation.

### Phase 2: Vote Casting (Voter Module)

Registered voters authenticate themselves and cast encrypted ballots through the voter interface. Each vote is encrypted using homomorphic encryption schemes and stored in the secure ballot box (Urna.txt). The system prevents double voting and maintains vote secrecy through advanced cryptographic protocols.

### Phase 3: Vote Tallying (Tally Module)

The tallying process verifies the validity of each vote, identifies the most recent valid ballot from each voter, and performs encrypted vote aggregation. This phase demonstrates the power of homomorphic encryption by enabling vote counting without decrypting individual ballots.

### Phase 4: Result Declaration (Counter Module)

The final phase announces election results while maintaining complete transparency and verifiability. The counter module provides cryptographic proofs that enable voters and observers to verify the integrity of the electoral process.

## Installation and Dependencies

### Required Libraries

The system requires several specialized cryptographic libraries that must be installed in specific locations:

**Microsoft SEAL (v3.4)**: Install the homomorphic encryption library with static library file (`libseal-3.4.a`) placed in `~/mylibs/lib/` and header files in `~/mylibs/include/SEAL-3.4/`. SEAL provides the core homomorphic encryption capabilities essential for privacy-preserving vote aggregation.

**OpenSSL**: Standard cryptographic library providing secure hash functions, digital signatures, and authenticated encryption. OpenSSL ensures the integrity and authenticity of communications between system components.

**Shamir's Secret Sharing CLI**: Install the `sss-cli` tool in `~/.cargo/bin/` to enable distributed key management and threshold cryptography. This component implements Shamir's Secret Sharing scheme for secure key distribution among trustees.

### Build Instructions

```bash
# Clone the repository
git clone https://github.com/esyker/Secure-Voting-System-Cpp
cd Secure-Voting-System-Cpp

# Ensure dependencies are properly installed
# Microsoft SEAL in ~/mylibs/
# OpenSSL (system-wide installation)
# sss-cli in ~/.cargo/bin/

# Build the system using the provided Makefile
make

# Verify all executables are generated
ls -la admin voter tally counter
```


## Usage Guide

### 1. Election Initialization

```bash
./admin
```

Configure election parameters including candidate count, voter registration, and trustee setup. The admin module establishes the cryptographic foundation for the entire electoral process.

### 2. Vote Casting

```bash
./voter
```

Each authorized voter executes the voter module, provides their voter identification, and selects candidates. Votes are automatically encrypted and stored in the secure ballot box.

### 3. Vote Counting

```bash
./tally
```

Process all cast votes, verify their validity, eliminate duplicate votes from the same voter, and perform encrypted vote aggregation using homomorphic encryption.

### 4. Result Announcement

```bash
./counter
```

Decrypt and announce final election results while providing cryptographic proofs for verification.

## Security Considerations

**Academic Implementation**: This system serves as a research prototype demonstrating advanced cryptographic voting techniques. While it implements state-of-the-art security measures, additional hardening would be necessary for production deployment.

**Cryptographic Assumptions**: Security relies on the hardness of lattice-based cryptographic problems underlying Microsoft SEAL's encryption schemes and the discrete logarithm assumption for secret sharing protocols.

**Trust Model**: The system assumes honest-but-curious administrators and requires threshold cooperation among trustees for vote decryption, distributing trust to prevent single points of compromise.

**Implementation Verification**: Users should conduct thorough security audits and formal verification of cryptographic implementations before considering deployment in real electoral scenarios.

## Technical Specifications

**Programming Language**: Modern C++ with emphasis on cryptographic library integration and secure memory management.

**Encryption Schemes**:

- Homomorphic encryption via Microsoft SEAL's BFV/CKKS schemes
- Symmetric encryption through OpenSSL
- Threshold cryptography using Shamir's Secret Sharing

**File Format**: Encrypted ballot storage in `Urna.txt` with authenticated encryption protecting vote integrity.

**Platform Compatibility**: Linux/Unix systems with C++ compilation environment and cryptographic library support.

## Research Context

This implementation contributes to the broader field of **cryptographic voting research** by demonstrating practical applications of homomorphic encryption in electoral systems. The system addresses fundamental challenges in electronic voting including vote privacy, verifiability, and coercion resistance through advanced cryptographic protocols.

The project aligns with modern voting system security standards that emphasize end-to-end verifiability, cryptographic vote protection, and distributed trust models. It serves as a valuable educational resource for understanding the intersection of cryptography and democratic processes.

## References

This implementation builds upon established research in cryptographic voting systems, homomorphic encryption applications, and secure multi-party computation protocols. Users are encouraged to consult academic literature on electronic voting security for comprehensive understanding of the theoretical foundations underlying this system.
