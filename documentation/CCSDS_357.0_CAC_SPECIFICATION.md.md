# CCSDS 357.0-B-1: CCSDS Authentication Credentials Specification

**Document Standard**: CCSDS 357.0-B-1 (Blue Book, Issue 1, July 2019\)  
**Security Baseline**: Systems Engineering Area / Security Working Group (SEA-SEC)  
**Classification**: Recommended Standard / Public Domain

---

## 1\. Executive Summary & Purpose

The **Consultative Committee for Space Data Systems (CCSDS) 357.0-B-1** Recommended Standard establishes a standardized profile for **Authentication Security Credentials** to enable mutual trust, authorization, and cryptographic access control across international space missions, commercial satellite constellations, and ground tracking networks.

In modern multi-agency and commercial space operations (such as NASA Artemis Lunar Gateway, US Space Force PWSA, ESA IRIS², and commercial ground station networks), disparate flight and ground nodes must verify the identities of remote communicators to prevent unauthorized command injection, eavesdropping, and masquerading attacks. CCSDS 357.0-B-1 defines two distinct credential profiles:

1. **X.509 v3 Space Profile**: High-assurance public key infrastructure (PKI) digital certificates conforming to IETF RFC 5280 and RFC 6818, specifically profiled for space data systems.  
2. **Protected Simple Authentication**: Low-overhead password and nonce-based authentication conforming to ISO/IEC 9594-8 (ITU-T X.511) Directory User Agent (DUA) to Directory System Agent (DSA) interactions.

---

## 2\. Technical Architecture & Protocols

\+-----------------------------------------------------------------------------+

\|               CCSDS 357.0-B-1 Authentication Credentials                    \|

\+--------------------------------------+--------------------------------------+

\|       X.509 v3 Space Profile         \|    Protected Simple Authentication   \|

\|   (Public Key Infrastructure \- PKI)  \|      (ISO/IEC 9594-8 / X.511)        \|

\+--------------------------------------+--------------------------------------+

\| • ASN.1 DER Hierarchical Framing     \| • Lightweight DUA \-\> DSA Protocol    \|

\| • Explicit Version 2 (X.509 v3)      \| • Pre-Shared Key / Bilateral Secret  \|

\| • GeneralizedTime (CCSDS 301.0-B-4)  \| • 128-bit Random Challenge Nonce     \|

\| • CCSDS 352.0-B-2 Algorithms         \| • CCSDS Calendar Segmented (CCS) Time\|

\| • BasicConstraints & KeyUsage Exts   \| • One-Way SHA-256 Digest Protection  \|

\| • SubjectAltName (SAN) & CRL Exts    \| • Replay & Delay Window Verification \|

\| • RFC 7292 PKCS\#12 Exchange Syntax   \| • Zero PKI Overhead for Constrained  \|

\+--------------------------------------+--------------------------------------+

---

## 3\. X.509 v3 Space Profile Normative Specifications

### 3.1 ASN.1 DER Structure

An X.509 v3 Space Profile Certificate conforms to the following ASN.1 structure (§3.1):

Certificate  ::=  SEQUENCE  {

     tbsCertificate       TBSCertificate,

     signatureAlgorithm   AlgorithmIdentifier,

     signatureValue       BIT STRING  }

TBSCertificate  ::=  SEQUENCE  {

     version         \[0\]  EXPLICIT Version DEFAULT v1,

     serialNumber         CertificateSerialNumber,

     signature            AlgorithmIdentifier,

     issuer               Name,

     validity             Validity,

     subject              Name,

     subjectPublicKeyInfo SubjectPublicKeyInfo,

     issuerUniqueID  \[1\]  IMPLICIT UniqueIdentifier OPTIONAL,

     subjectUniqueID \[2\]  IMPLICIT UniqueIdentifier OPTIONAL,

     extensions      \[3\]  EXPLICIT Extensions OPTIONAL

     }

### 3.2 Normative Profile Constraints

- **Version (§3.1.1)**: Must be X.509 v3, encoded as contextual tag `[0]` containing `INTEGER 2`.  
- **Time Representation (§3.1.2 & §3.1.3)**: `validity` fields (`notBefore` and `notAfter`) must be encoded as `GeneralizedTime` (Tag `0x18`) using the CCSDS Calendar Segmented (CCS) time code format: `YYYYMMDDHHMMSSZ` per CCSDS 301.0-B-4. UTC Time (Tag `0x17`) is restricted to legacy profiles.  
- **Cryptographic Algorithms (§3.1.5)**: Must utilize digital signature algorithms specified in CCSDS 352.0-B-2 (e.g., `sha256WithRSAEncryption` OID `1.2.840.113549.1.1.11` or `ecdsa-with-SHA256` OID `1.2.840.10045.4.3.2`).  
- **Output Exchange Syntax (§3.1.4)**: Portable certificate and private key exchange bundles must utilize PKCS\#12 (Personal Information Exchange Syntax, RFC 7292).

---

## 4\. Protected Simple Authentication (ISO/IEC 9594-8)

For resource-constrained spacecraft or flight computers unable to support full public key validation paths, CCSDS 357.0-B-1 Section 3.2 allows **Protected Simple Authentication**:

### 4.1 Wire Protocol & Mathematical Formulation

The Directory User Agent (DUA) authenticates to the Directory System Agent (DSA) by transmitting:

1. Subscriber Distinguished Name (\$DN\$)  
2. Fresh 128-bit Cryptographic Nonce (\$N\$)  
3. CCSDS Segmented Calendar Timestamp (\$T\_{\\text{CCS}}\$) formatted as `YYYY-MM-DDTHH:MM:SSZ`  
4. One-Way Protected Hash Token (\$H\_{\\text{auth}}\$):

\$\$H\_{\\text{auth}} \= \\text{SHA-256}(DN \\parallel \\text{Password} \\parallel N \\parallel T\_{\\text{CCS}})\$\$

### 4.2 DSA Verification & Replay Protection

1. **Nonce Freshness**: DSA maintains a seen nonce window to prevent telecommand replay injection.  
2. **Timestamp Drift Tolerance**: DSA verifies \$\|T\_{\\text{recv}} \- T\_{\\text{CCS}}\| \\le \\Delta t\_{\\text{drift}}\$ to prevent delayed packet spoofing over variable space links.  
3. **Cryptographic Validation**: DSA re-computes \$H\_{\\text{expected}}\$ using stored bilateral secret; match grants access.

---

## 5\. Annex A Implementation Conformance Statement (ICS) Requirements List

CCSDS 357.0-B-1 Annex A specifies 23 normative items for space credential engines:

- **Mandatory (M)**: ASN.1 (Item 1), DER (Item 2), X.509.V3 (Item 3), TBSCertificate (Item 4), Version (Item 5), Serial Number (Item 6), Algorithm ID (Item 7), Issuer Signature (Item 8), Validity from (Item 9), Validity to (Item 10), Subject (Item 11), Subject Algorithm ID (Item 12), Subject Public Key (Item 13), UTC Reference (Item 16), GeneralizedTime (Item 17), Signature Algorithm (Item 22), Signature Value (Item 23).  
- **Optional (O)**: Issuer Unique ID (Item 14), Subject Unique ID (Item 15), OIDs (Item 18), Policy Mapping (Item 19), Subject Alternative Name (Item 20), CRL Distribution Points (Item 21).