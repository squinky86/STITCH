# STITCH Score Estimation

| Version | Date       | Author(s) | Remarks         |
| :------ | :--------- | :-------- | :-------------- |
| 0.1.0   | 2025-10-19 | Jon Hood  | Initial Draft   |

---

## 1.0 Purpose

This document is maintained as part of the Scoring Tool for Integrated Threat and Compliance Heuristics (STITCH) project. It establishes the STITCH Score Estimation (SSE), a methodology for assessing and prioritizing software weaknesses identified by Application Security Testing (AST) tools, including Static (SAST), Dynamic (DAST), Interactive (IAST), and Software Composition Analysis (SCA).

The primary goals of SSE are to:
1.  Provide a repeatable and consistent framework for scoring software weaknesses based on their exploitability, impact, and the confidence of the analyst.
2.  Generate a risk-based score to guide remediation efforts and prioritize findings.
3.  Provide a mechanism to estimate an equivalent Common Vulnerability Scoring System (CVSS) v4.0 score for standardized reporting.

## 2.0 Scope

This standard applies to all software weaknesses, flaws, and potential vulnerabilities discovered in source code, binaries, or running applications below the system level during the software development lifecycle. It is intended for use by security analysts, developers, and program managers to triage and manage findings from automated security tools.

This standard does not apply to system-level attributes, operational environment misconfigurations, network-level vulnerabilities, or physical security weaknesses.

## 3.0 Definitions and Acronyms

| Term | Definition |
| :--- | :--- |
| **Analyst** | The individual responsible for reviewing a finding and applying the SSE framework |
| **AST** | Application Security Testing |
| **CVE** | Common Vulnerabilities and Exposures |
| **CVSS** | Common Vulnerability Scoring System |
| **CWE** | Common Weakness Enumeration |
| **DAST** | Dynamic AST |
| **Finding** | A potential weakness reported against a cybersecurity standard |
| **FIRST** | Forum of Incident Response and Security Teams, Inc. |
| **IAST** | Interactive AST |
| **NVD** | National Vulnerability Database |
| **SAST** | Static AST |
| **SCA** | Software Composition Analysis |
| **SSE** | STITCH Score Estimation |
| **STITCH** | Scoring Tool for Integrated Threat and Compliance Heuristics |
| **Vulnerability** | A weakness that has been confirmed to be exploitable and impacts the security of a system |
| **Weakness** | A flaw or error in software design, code, or implementation that, if exploited, could lead to a security breach |

## 4.0 Scoring Methodology

ESS combines two sources of data to create its scoring estimations:
* MITRE's CWEs
* NVD's CVEs

### 4.1 Indexing Data

The CWE and CVE data are indexed from their respective data feed.

#### 4.1.1 CWE Indexing

Modifications to the CWE data are made such that CWEs, such as some Classes, with varying impacts are assumed to be able to impact all three factors of Confidentiality, Integrity, and Availability. All other CWE data is used as-is.

#### 4.1.2 CVE Indexing

Only the highest CVSS version of Primary NVD scores are preserved for each CVE. All scores are converted to CVSS Version 4.0.

When the highest Primary score is in CVSS version 3.0 or 3.1, the following conversions are used. All other attributes are copied to the CVSS 4.0 score.

| CVSS 3.0 or 3.1 | CVSS 4.0 |
| :--- | :--- |
| Attack Vector  (AV) | Access Vector (AV) |
| AV: `ADJACENT_NETWORK` | AV: `ADJACENT` |
| UI: `REQUIRED` | UI: `ACTIVE` |
| S: `CHANGED` | SC, SI, SA: set to C, I, and A respectively |
| S: `UNCHANGED` | SC, SI, SA: set to `NONE` |

When the highest primary score is in CVSS version 2.0, the following conversions are used. All other attributes are copied to the CVSS 4.0 score.

| CVSS 2.0 | CVSS 4.0 |
| :--- | :--- |
| Attack Vector  (AV) | Access Vector (AV) |
| AV: `ADJACENT_NETWORK` | AV: `ADJACENT` |
| Access Complexity (AC) | Attack Complexity (AC) and Attack Requirements (AR) |
| AC: `LOW` | AC: `LOW`, AR: `NONE` |
| AC: `MEDIUM` | AC: `LOW`, AR: `PRESENT` |
| AC: `HIGH` | AC: `HIGH`, AR: `PRESENT` |
| Authentication (AU) | Privileges Required (PR) |
| AU: `MULTIPLE` | PR: `HIGH` |
| AU: `SINGLE` | PR: `LOW` |
| C, I, A Impact (C, I, A) | Vulnerability C, I, A Impact (VC, VI, VA) |
| C, I, A: `PARTIAL` | VC, VI, VA: `LOW` |
| C, I, A: `COMPLETE` | VC, VI, VA: `HIGH` |

The NVD also keeps up with the following attributes to aide in CVSS 4.0 scoring conversion.

| NVD CVSS 2.0 Score Attribute | CVSS 4.0 |
| :--- | :--- |
| User Interaction Required | User Interaction (UI) |
| User Interaction Required true | UI: `REQUIRED` |
| Obtain All Privilege, Obtain User Privilege, and Obtain Other Privilege | Subsystem C, I, and A (SC, SI, SA) |
| Obtain All Privilege | SC, SI, SA: `HIGH` |
| Obtain User Privilege | SC, SI, SA: `LOW` (when Obtain All Privilege is not set) |
| Obtain Other Privilege | SC, SI, SA: `LOW` (when Obtain All Privilege is not set) |
| Obtain All/User/Other Privilege is NOT set | SC, SI, SA: `NONE` |

### 4.2 Score Calculation

todo

## Appendix A: References

*   Forum of Incident Response and Security Teams, Inc. (FIRST). [CVSS Specification](https://www.first.org/cvss/v4.0/specification-document) V4.0.
*  MITRE Corporation. [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) V4.18.
