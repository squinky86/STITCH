> **UNCLASSIFIED**  
> **DISTRIBUTION STATEMENT A: Approved for public release. Distribution is unlimited.**

# STITCH Score Estimation

| Version | Date       | Author(s) | Remarks                |
| :------ | :--------- | :-------- | :--------------------- |
| 0.1.0   | 2025-10-19 | Jon Hood  | Initial Public Release |

## Copyright, Acknowledgements, and Licensing Information

**Copyright © 2025 Jon Hood**

The STITCH Score Estimation software is licensed under the MIT license. A copy of the `LICENSE` is distributed with the software.

This documentation and process are licensed under the **Creative Commons Attribution 4.0 International License (CC BY 4.0)**.

To view a copy of this license, visit: <[https://creativecommons.org/licenses/by/4.0/](https://creativecommons.org/licenses/by/4.0/)>.

This process was developed, in whole or in part, under U.S. Government Contract No. ending in 24-F-B013 with the U.S. Army, DEVCOM AvMC. For the full contract number, please contact the author(s) of this process.

Any opinions, findings, and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the U.S. Army or the Department of Defense.

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
| **ASD** | Application Security and Development |
| **AST** | Application Security Testing |
| **CCI** | Control Correlation Identifier |
| **CVE** | Common Vulnerabilities and Exposures |
| **CVSS** | Common Vulnerability Scoring System |
| **CWE** | Common Weakness Enumeration |
| **DAST** | Dynamic AST |
| **Finding** | A potential weakness reported against a cybersecurity standard |
| **FIRST** | Forum of Incident Response and Security Teams, Inc. |
| **IAST** | Interactive AST |
| **NIST** | National Institute of Standards and Technology |
| **NVD** | National Vulnerability Database |
| **RMF** | Risk Management Framework |
| **SAST** | Static AST |
| **SCA** | Software Composition Analysis |
| **SSE** | STITCH Score Estimation |
| **STIG** | Security Technical Implementation Guide |
| **STIGWE** | STIG Weakness Enumerations |
| **STITCH** | Scoring Tool for Integrated Threat and Compliance Heuristics |
| **Vulnerability** | A weakness that has been confirmed to be exploitable and impacts the security of a system |
| **Weakness** | A flaw or error in software design, code, or implementation that, if exploited, could lead to a security breach |

## 4.0 Scoring Methodology

SSE combines two sources of data to create its scoring estimations:
* MITRE's CWEs
* NVD's CVEs

## 4.1 Indexing Data

The CWE and CVE data are indexed from their respective data feed.

### 4.1.1 CWE Indexing

Modifications to the CWE data are made such that CWEs, such as some Classes, with varying, `Other` impacts are assumed to be able to impact all three factors of Confidentiality, Integrity, and Availability. All other CWE data is used as-is. Additional impact rules to follow are:

* CWEs that have an impact of `Authentication` or `Authorization` affect Confidentiality, Integrity, and Availability.
* CWEs that affect `Access Control` affect Confidentiality and Integrity.
* CWEs that affect `Non-Repudiation` affect Integrity.

### 4.1.2 CVE Indexing

Only the highest CVSS version of Primary NVD scores are preserved for each CVE. All scores are converted to CVSS Version 4.0.

When the highest Primary score is in CVSS version 3.0 or 3.1, the following conversions are used. All other attributes are copied to the CVSS 4.0 score.

| CVSS 3.0 or 3.1 | CVSS 4.0 |
| :--- | :--- |
| Attack Vector (AV) | Access Vector (AV) |
| AV: `ADJACENT_NETWORK` | AV: `ADJACENT` |
| UI: `REQUIRED` | UI: `ACTIVE` |
| S: `CHANGED` | SC, SI, SA: set to C, I, and A respectively |
| S: `UNCHANGED` | SC, SI, SA: set to `NONE` |

When the highest primary score is in CVSS version 2.0, the following conversions are used. All other attributes are copied to the CVSS 4.0 score.

| CVSS 2.0 | CVSS 4.0 |
| :--- | :--- |
| Attack Vector (AV) | Access Vector (AV) |
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

The NVD also keeps up with the following attributes which can assist in CVSS 4.0 scoring conversion.

| NVD CVSS 2.0 Score Attribute | CVSS 4.0 |
| :--- | :--- |
| User Interaction Required | User Interaction (UI) |
| User Interaction Required true | UI: `ACTIVE` |
| Obtain All Privilege, Obtain User Privilege, and Obtain Other Privilege | Subsystem C, I, and A (SC, SI, SA) |
| Obtain All Privilege | SC, SI, SA: `HIGH` |
| Obtain User Privilege | SC, SI, SA: `LOW` (when Obtain All Privilege is not set) |
| Obtain Other Privilege | SC, SI, SA: `LOW` (when Obtain All Privilege is not set) |
| Obtain All/User/Other Privilege is NOT set | SC, SI, SA: `NONE` |

## 4.2 Score Estimation

Estimating a score is done by CWE. For a given CWE, the closest associated CVEs are grouped to find the score estimation. The method for finding the closest available CVEs and then using them to estimate the overall CWE score is described in this section.

### 4.2.1 Finding Associated CVEs

Each round in this process is composed of varying steps. After each round, if at least five CVEs (defined as `MINIMUM_CVES_TO_SCORE = 5`) are associated with the CWEs, the results are calculated, and the subsequent rounds are not performed. If there are not at least five unique CVEs after a round, the next round is performed. During a round, there are multiple steps. If after a step there are at least 50 CVEs (defined as `MINIMUM_CVES_TO_COMPLETE_ROUND = 50`) identified, the subsequent steps are not performed.

#### 4.2.1.1 Round 1: Direct CVEs

During Round 1, CVEs mapped directly to the requested CWE are used to determine the estimated score.

##### 4.2.1.1.1 Round 1 Step 1: Direct CVEs with CVSS 4.0 Scores

CVEs with a Primary NVD Score using CVSS 4.0 mapped to the CWE are obtained and added to the list of CVEs to use to score the CWE.

##### 4.2.1.1.2 Round 1 Step 2: Direct CVEs with CVSS 3.0 or CVSS 3.1 Scores

CVEs with a Primary NVD Score using CVSS 3.0 or 3.1 mapped to the CWE are obtained, converted to CVSS 4.0 scores using the conversion process in Section 4.1.2, and added to the list of CVEs to use to score the CWE.

##### 4.2.1.1.3 Round 1 Step 3: Direct CVEs with CVSS 2.0 Scores

CVEs with a Primary NVD Score using CVSS 2.0 mapped to the CWE are obtained, converted to CVSS 4.0 scores using the conversion process in Section 4.1.2, and added to the list of CVEs to use to score the CWE.

#### 4.2.1.2 Round 2: Progeny CVEs

During Round 2, CVEs directly mapped to increasingly subsequent rounds of child CWEs using only children associated with the CWE-1000 View are collected. The children of the CWE under consideration proceed through the steps of Round 2. If there are not at least `MINIMUM_CVES_TO_SCORE` after a round, the next generation of progeny repeat Round 2. This progresses until all progeny are evaluated. As the CWE data may contain loops and to avoid counting CVEs multiple times, progeny that have already been traversed are removed from consideration for subsequent rounds. I.E., Round 2 is performed for child CWEs, then grandchild CWEs, then great-grandchild CWEs, etc. until all progeny generations of CWEs are exhausted.

##### 4.2.1.2.1 Round 2 Step 1: Progeny CVEs with CVSS 4.0 Scores

CVEs with a Primary NVD Score using CVSS 4.0 mapped to the CWE's progeny generation are obtained and added to the list of CVEs to use to score the CWE.

##### 4.2.1.2.2 Round 2 Step 2: Progeny CVEs with CVSS 3.0 or CVSS 3.1 Scores

CVEs with a Primary NVD Score using CVSS 3.0 or 3.1 mapped to the CWE's progeny generation are obtained, converted to CVSS 4.0 scores using the conversion process in Section 4.1.2, and added to the list of CVEs to use to score the CWE.

##### 4.2.1.2.3 Round 2 Step 3: Progeny CVEs with CVSS 2.0 Scores

CVEs with a Primary NVD Score using CVSS 2.0 mapped to the CWE's progeny generation are obtained, converted to CVSS 4.0 scores using the conversion process in Section 4.1.2, and added to the list of CVEs to use to score the CWE.

#### 4.2.1.3 Round 3: Ancestor CVEs

During Round 3, CVEs directly mapped to the CWE's ancestor generations are evaluated. Note that Round 3 is only iterated for increasingly distant ancestor CWEs after the completion of Round 4 using only ancestors associated with the CWE-1000 View. The ancestors of the CWE under consideration proceed through the steps of Round 3.

##### 4.2.1.3.1 Round 3 Step 1: Ancestor CVEs with CVSS 4.0 Scores

CVEs with a Primary NVD Score using CVSS 4.0 mapped to the CWE's ancestor generation are obtained and added to the list of CVEs to use to score the CWE.

##### 4.2.1.3.2 Round 3 Step 2: Ancestor CVEs with CVSS 3.0 or CVSS 3.1 Scores

CVEs with a Primary NVD Score using CVSS 3.0 or 3.1 mapped to the CWE's ancestor generation are obtained, converted to CVSS 4.0 scores using the conversion process in Section 4.1.2, and added to the list of CVEs to use to score the CWE.

##### 4.2.1.3.3 Round 3 Step 3: Ancestor CVEs with CVSS 2.0 Scores

CVEs with a Primary NVD Score using CVSS 2.0 mapped to the CWE's ancestor generation are obtained, converted to CVSS 4.0 scores using the conversion process in Section 4.1.2, and added to the list of CVEs to use to score the CWE.

#### 4.2.1.4 Round 4: Cousin CVEs

During Round 4, CVEs directly mapped to the CWE's ancestor generation's direct children are evaluated. The cousins of the CWE under consideration proceed through the steps of Round 4. If there are not at least `MINIMUM_CVES_TO_SCORE` after a round, the previous generation of ancestors repeat at Round 3. This progresses until all ancestors are evaluated. As the CWE data may contain loops and to avoid counting CVEs multiple times, ancestors and cousins that have already been traversed are removed from consideration for subsequent rounds. I.E., Round 3 is performed for parent CWEs, then Round 4 is performed for all siblings, then Round 3 is performed for all grandparent CWEs, then round 4 is performed for all first cousins, then great-grandparents and second cousins, etc. until all ancestor generations of CWEs are exhausted.

##### 4.2.1.4.1 Round 4 Step 1: Cousin CVEs with CVSS 4.0 Scores

CVEs with a Primary NVD Score using CVSS 4.0 mapped to the CWE's ancestor generation children (cousins) are obtained and added to the list of CVEs to use to score the CWE.

##### 4.2.1.4.2 Round 4 Step 2: Cousin CVEs with CVSS 3.0 or CVSS 3.1 Scores

CVEs with a Primary NVD Score using CVSS 3.0 or 3.1 mapped to the CWE's ancestor generation children (cousins) are obtained, converted to CVSS 4.0 scores using the conversion process in Section 4.1.2, and added to the list of CVEs to use to score the CWE.

##### 4.2.1.4.3 Round 4 Step 3: Cousin CVEs with CVSS 2.0 Scores

CVEs with a Primary NVD Score using CVSS 2.0 mapped to the CWE's ancestor generation children (cousins) are obtained, converted to CVSS 4.0 scores using the conversion process in Section 4.1.2, and added to the list of CVEs to use to score the CWE.

### 4.2.2 Estimating the Score

With the set of CVEs obtained from Section 4.2.1, the parameters for a new CVSS 4.0 score are set.

* Attack Vector (AV) is set to the mode of Attack Vectors in the set of CVEs.
* Attack Complexity (AC) is set to the mode of Attack Complexities in the set of CVEs.
* Attack Requirements (AR) is set to the mode of Attack Requirements in the set of CVEs.
* Privileges Required (PR) is set to the mode of Privileges Required in the set of CVEs.
* User Interaction (UI) is set to the mode of User Interactions in the set of CVEs.
* Confidentiality Impact to the Vulnerable System (VC) is set to the weighted mean of Confidentiality Impacts to the Vulnerable System in the set of CVEs. The weighted mean formula is defined in Section 4.2.2.1.
* Integrity Impact to the Vulnerable System (VI) is set to the weighted mean of Integrity Impacts to the Vulnerable System in the set of CVEs.
* Availability Impact to the Vulnerable System (VA) is set to the weighted mean of Availability Impacts to the Vulnerable System in the set of CVEs.
* Confidentiality Impact to the Subsequent System (SC) is set to the weighted mean of Confidentiality Impacts to the Subsequent System in the set of CVEs.
* Integrity Impact to the Subsequent System (SI) is set to the weighted mean of Integrity Impacts to the Subsequent System in the set of CVEs.
* Availability Impact to the Subsequent System (SA) is set to the weighted mean of Availability Impacts to the Subsequent System in the set of CVEs.

#### 4.2.2.1 Weighted Mean Calculation

CVEs with an impact of `HIGH` are weighted with a value of 3. CVEs with an impact of `LOW` are weighted with a value of 1. CVEs with an impact of `NONE` are weighted with a value of 0. The weighted average (w) is the sum of all values (v) divided by the total number of CVEs (n).

$$
w = \frac{\sum_{i=1}^{n} v_i}{n}
$$

When w is less than 0.33, the weighted mean is set to `NONE`. When w is 0.33 to 2.0, the weighted mean is set to `LOW`. When w is 2.0 or greater, the weighted mean is set to `HIGH`.

## 4.3 Supplemental Information

STITCH includes associating scores against the Application Security and Development (ASD) Security Technical Implementation Guide (STIG) and Risk Management Framework (RMF) Control Correlation Identifiers (CCIs).

* The latest ASD STIG is pulled from [https://public.cyber.mil/](https://public.cyber.mil/).
* The latest RMF Control information is pulled from [https://csrc.nist.gov/](https://csrc.nist.gov/).
* The latest CCI information is pulled from [https://public.cyber.mil/](https://public.cyber.mil/).
* Associations between the ASD STIG and CWEs are obtained from the [STIGWE project](https://www.github.com/squinky86/STIGWE).

## Appendix A: References

*  Forum of Incident Response and Security Teams, Inc. (FIRST). [CVSS Specification](https://www.first.org/cvss/v4.0/specification-document) V4.0.
*  Hood, Jon. [STIG Weakness Enumerations (STIGWE)](https://www.github.com/squinky86/STIGWE).
*  MITRE Corporation. [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) V4.18.
*  National Institute of Standards and Technology (NIST). [National Vulnerability Database (NVD)](https://nvd.nist.gov/).
*  National Institute of Standards and Technology. "Security and Privacy Controls for Information Systems and Organizations." Computer Security Resource Center, Special Publication 800-53, Revision 5, Update 1, U.S. Department of Commerce, 15 Sept. 2020, [https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
*  U.S. Department of Defense. [DoD Cyber Exchange](https://public.cyber.mil/).
