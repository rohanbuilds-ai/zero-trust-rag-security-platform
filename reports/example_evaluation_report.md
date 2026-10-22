# Zero-Trust RAG Security Evaluation & Benchmark Report (Example Synthetic Benchmark)

**Schema Version:** `1.0.0`
**Execution Mode:** Ephemeral In-Memory Vector Store & SQLite Isolation
**Overall Status:** **PASSED (ALL CRITERIA MET)**

---

## 1. Hard Security Acceptance Criteria

| Security Invariant Criterion | Status | Target | Observation |
| :--- | :---: | :---: | :---: |
| Zero Cross-Tenant Leakage | ✅ PASS | 0.0% | 0.0% |
| Zero Unauthorized Content Disclosed | ✅ PASS | 0.0% | 0.0% |
| Zero Revoked Content Exposed | ✅ PASS | 0.0% | 0.0% |
| Zero Tampered Chunks Accepted | ✅ PASS | 0.0% | 0.0% |
| Zero Plaintext Sensitive Values in Egress | ✅ PASS | 0.0% | 0.0% |
| Zero Revoked Document Reactivation | ✅ PASS | 0.0% | Permitted: 0 |

---

## 2. Quantitative Security Metrics

| Metric | Measured Value | Standard / Description |
| :--- | :---: | :--- |
| **Prompt Injection Recall** | `100.0%` | Fraction of suspicious documents detected by inspector rules |
| **Prompt Injection Precision** | `100.0%` | Precision of inspector rules against benign controls |
| **Benign Quarantine Rate** | `0.0%` | False-positive quarantine rate on legitimate prose |
| **Cross-Tenant Leakage Rate** | `0.0%` | Unauthorized exposure across tenant boundary (Must be 0.0%) |
| **Unauthorized Rejection Rate** | `100.0%` | Rate of unauthorized requests rejected authoritatively |
| **Revocation Enforcement Rate** | `100.0%` | Rate of revoked content blocked from retrieval |
| **Content Integrity Rejection Rate** | `100.0%` | Rate of tampered chunks detected and excluded |
| **Citation Integrity Rate** | `100.0%` | Rate of citations strictly matching accepted context passages |
| **DLP Recall** | `100.0%` | Fraction of labeled sensitive values successfully redacted |
| **DLP Precision** | `100.0%` | Precision of DLP replacements against false positives |
| **Benign False-Redaction Rate** | `0.0%` | Normal numbers unnecessarily redacted |

---

## 3. Operational Performance & Audit Metrics

- **Total Scenarios Executed:** 170
- **Total Passed:** 170 (100.0%)
- **Total Failed:** 0
- **Execution Duration:** 9.07s
- **Mean Latency:** 53.36 ms
- **Median Latency (p50):** 52.02 ms
- **95th Percentile Latency (p95):** 114.6 ms
- **Audit Events Generated:** 1000
- **Audit Trail Integrity:** Verified Immutable

---

## 4. Category Performance Summary

| Category | Total | Passed | Failed | Pass Rate | Avg Latency (ms) | p95 Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `prompt_injection` | 52 | 52 | 0 | 100.0% | 81.7 | 116.95 |
| `access_control` | 32 | 32 | 0 | 100.0% | 71.8 | 134.0 |
| `dlp_sensitive_data` | 32 | 32 | 0 | 100.0% | 0.04 | 0.15 |
| `content_integrity` | 22 | 22 | 0 | 100.0% | 50.81 | 112.18 |
| `benign_usability` | 32 | 32 | 0 | 100.0% | 43.94 | 83.96 |

---

## 5. Failed Scenarios

🎉 **Zero failed scenarios.** All 170 adversarial and operational benchmarks met expected outcomes.
