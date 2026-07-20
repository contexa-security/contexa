package io.contexa.contexacore.verification.metric;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

/**
 * Versioned OSS source of truth for the persisted official-verification
 * definition catalog. Row counts are derived from the canonical key sets.
 */
public final class OfficialVerificationDefinitionCatalog {

    public static final String VERSION = "2026.05.01-pqa12-p1";

    private static final List<MetricSeed> METRICS = List.of(
            new MetricSeed("EIR", "Evidence Integrity and Representativeness", "sealed-evidence",
                    "Verifies that sealed request evidence represents the actual request and final prompt input.",
                    "packageId, request facts, auth state, prompt hash, prompt execution metadata", "PROMPT_QUALITY"),
            new MetricSeed("CCR", "Context Completeness Rate", "context-completeness",
                    "Verifies that required request, auth, resource, baseline, RAG, and governance contexts are present.",
                    "request facts, auth state, protectable metadata, baseline snapshot, RAG results, prompt governance", "PROMPT_QUALITY"),
            new MetricSeed("CCSR", "Context Consistency Rate", "context-consistency",
                    "Verifies that request facts, prompt facts, hashes, and sealed evidence do not contradict each other.",
                    "request facts, prompt facts, sealed package facts, prompt execution metadata", "PROMPT_QUALITY"),
            new MetricSeed("PFR", "Prompt Fidelity Rate", "prompt-fidelity",
                    "Verifies that the final system/user prompt follows the official prompt contract and traceability rules.",
                    "system/user prompt text, raw/final prompt trace, prompt budget, prompt contract counters", "PROMPT_QUALITY"),
            new MetricSeed("MTR", "Metric Traceability and Reproducibility", "traceability",
                    "Verifies that the metric result can be reproduced from sealed package identity, hash, and retention facts.",
                    "package hash, prompt hash, sealed flag, capture time, expiry time, schema version", "PROMPT_QUALITY"),
            new MetricSeed("CoR", "Context Contamination Rate", "context-contamination",
                    "Verifies that documents entering the prompt stay within tenant, user, resource, and purpose boundaries.",
                    "RAG related documents with tenant/user/resource/purpose scope metadata", "PROMPT_QUALITY"),
            new MetricSeed("RAP", "RAG Authorization Precision", "rag-authorization",
                    "Verifies that every document included in final context has explicit authorization and permission evidence.",
                    "RAG related documents with authorization decision, permission scope, and inclusion state", "PROMPT_QUALITY"),
            new MetricSeed("RPI", "Round Prompt Invariance", "round-consistency",
                    "Verifies that re-verification rounds preserve core security facts and do not regress evidence quality.",
                    "prior sealed packages for same user/resource window and latest round prompt facts", "PROMPT_QUALITY"),
            new MetricSeed("BMA", "Baseline Maturity Accuracy", "learning-baseline",
                    "Verifies that learning baseline maturity claims match observation depth, coverage, and fallback ratio.",
                    "baseline maturity state, observation days, event count, coverage, fallback ratio", "PROMPT_QUALITY"),
            new MetricSeed("USNS", "User-Specific Novelty Sensitivity", "user-novelty",
                    "Verifies that user-specific novelty signals are structured and reflected in the prompt.",
                    "baseline novelty signals and user prompt reflection for time, network, browser, device, and request combination", "PROMPT_QUALITY"),
            new MetricSeed("BSR", "Behavioral Surprise Resolution", "behavior-context",
                    "Verifies that behavioral surprise is explained with baseline and resolution context rather than naked labels.",
                    "canonical behavior context and prompt explanation of baseline/observed/resolution facts", "PROMPT_QUALITY"),
            new MetricSeed("PRE", "Protectable Resource Eligibility", "resource-eligibility",
                    "Verifies that the actual requested resource is bound to the @Protectable target eligible for certification.",
                    "protectable resource metadata, actual request path, actual resource id, HTTP method", "PROMPT_QUALITY")
    );

    private static final List<CheckSeed> SPECIFIC_CHECKS = List.of(
            new CheckSeed("EIR", "EIR_MFA_STATE_PROMPT_MATCH",
                    "MFA state in auth evidence matches the final user prompt",
                    "same key and value in authState and userPromptText",
                    "sealedEvidence.authState.mfaVerified|userPromptText", "BLOCKING", "PROMPT_ASSEMBLER"),
            new CheckSeed("CCR", "CCR_AUTH_CONTEXT_COMPLETE",
                    "Authentication context contains required method, MFA, role, permission, and authorization facts",
                    "complete auth context", "sealedEvidence.authState", "BLOCKING", "AUTH_CONTEXT"),
            new CheckSeed("CCSR", "CCSR_PROMPT_HASH_LEDGER_MATCH",
                    "Declared prompt hash matches sealed prompt metadata",
                    "same prompt hash in package and metadata",
                    "sealedEvidence.promptHash|promptExecutionMetadata.promptHash", "BLOCKING", "PROMPT_CAPTURE"),
            new CheckSeed("PFR", "PFR_CONTRACT_VIOLATION_ZERO",
                    "Prompt contract violation count is zero", "0 contract violations",
                    "sealedEvidence.promptExecutionMetadata.promptContractViolationCount", "BLOCKING", "PROMPT_GOVERNANCE"),
            new CheckSeed("MTR", "MTR_EXPIRY_PRESENT",
                    "Sealed evidence has a retention expiry timestamp", "expiresAt present",
                    "sealedEvidence.expiresAt", "BLOCKING", "EVIDENCE_STORE"),
            new CheckSeed("CoR", "COR_PURPOSE_MISMATCH_ZERO",
                    "No retrieved document violates the request purpose boundary", "purposeMismatchCount is zero",
                    "sealedEvidence.ragResults.purposeMismatchCount", "BLOCKING", "RAG_CONTEXT"),
            new CheckSeed("RAP", "RAP_DOC_AUTH_DECISION_PRESENT_1",
                    "Included document has an explicit authorization decision", "authorizationDecision present",
                    "sealedEvidence.ragResults.relatedDocuments[1].authorizationDecision", "BLOCKING", "RAG_AUTHORIZATION"),
            new CheckSeed("RAP", "RAP_DOC_INCLUDED_IS_AUTHORIZED_1",
                    "Included document is authorized before it enters final prompt context",
                    "final included document authorized",
                    "sealedEvidence.ragResults.relatedDocuments[1].finalContextIncluded|authorizationDecision",
                    "BLOCKING", "RAG_AUTHORIZATION"),
            new CheckSeed("RAP", "RAP_DOC_PERMISSION_SCOPE_PRESENT_1",
                    "Included document has permission scope evidence", "permissionScope present",
                    "sealedEvidence.ragResults.relatedDocuments[1].permissionScope", "BLOCKING", "RAG_AUTHORIZATION"),
            new CheckSeed("RPI", "RPI_RELATED_DOCUMENTS_NON_REGRESSIVE",
                    "Related document count does not regress across verification rounds",
                    "non-regressive related document count",
                    "sealedEvidence.repository.priorPackages.ragResults.relatedDocuments", "BLOCKING", "EVIDENCE_STORE"),
            new CheckSeed("BMA", "BMA_MATURITY_NOT_OVERCLAIMED",
                    "Baseline maturity is not overclaimed beyond observed data depth",
                    "maturity consistent with observation depth", "sealedEvidence.baselineSnapshot",
                    "BLOCKING", "LEARNING_CONTEXT"),
            new CheckSeed("USNS", "USNS_TIME_PROMPT_REFLECTS_SIGNAL",
                    "Time novelty signal is reflected in the final user prompt",
                    "prompt mentions time novelty signal",
                    "sealedEvidence.baselineSnapshot.noveltySignals.time|userPromptText", "BLOCKING", "PROMPT_ASSEMBLER"),
            new CheckSeed("BSR", "BSR_PROMPT_EXPLAINS_BEHAVIOR",
                    "Prompt explains behavior with baseline or observed work pattern context",
                    "behavior baseline explanation present", "sealedEvidence.canonicalContext|userPromptText",
                    "BLOCKING", "PROMPT_ASSEMBLER"),
            new CheckSeed("PRE", "PRE_RESOURCE_ID_BOUND_TO_ACTUAL",
                    "Protectable resource template is bound to the actual request resource value",
                    "actual resource id bound to @Protectable template",
                    "sealedEvidence.requestFacts.protectableResourceId|requestFacts.resourceId",
                    "BLOCKING", "PROTECTABLE_RESOURCE")
    );

    private OfficialVerificationDefinitionCatalog() {
    }

    public static List<MetricSeed> metrics() {
        return METRICS;
    }

    public static List<CheckSeed> checks() {
        List<CheckSeed> registrationChecks = METRICS.stream()
                .map(metric -> new CheckSeed(
                        metric.code(),
                        metric.code() + "_OFFICIAL_CONTRACT",
                        metric.name() + " official contract is registered",
                        "active metric definition",
                        "official_verification_metric_definition",
                        "BLOCKING",
                        "PQA_RUNTIME"))
                .toList();
        return Stream.concat(registrationChecks.stream(), SPECIFIC_CHECKS.stream()).toList();
    }

    public static String checksum() {
        StringBuilder canonical = new StringBuilder(VERSION).append('\n');
        METRICS.forEach(metric -> canonical.append("M|").append(metric.canonical()).append('\n'));
        checks().forEach(check -> canonical.append("C|").append(check.canonical()).append('\n'));
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required", e);
        }
    }

    public record MetricSeed(
            String code,
            String name,
            String group,
            String purpose,
            String evidenceContract,
            String blockingScope) {

        private String canonical() {
            return String.join("|", code, name, group, purpose, evidenceContract, blockingScope);
        }
    }

    public record CheckSeed(
            String metricCode,
            String checkCode,
            String label,
            String expectedValue,
            String evidenceSource,
            String severity,
            String remediationOwner) {

        private String canonical() {
            return String.join("|", metricCode, checkCode, label, expectedValue,
                    evidenceSource, severity, remediationOwner);
        }
    }
}
