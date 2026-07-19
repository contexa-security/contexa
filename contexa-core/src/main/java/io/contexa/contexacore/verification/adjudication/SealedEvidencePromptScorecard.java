package io.contexa.contexacore.verification.adjudication;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;

/**
 * Evaluates a sealed evidence package against prompt quality checks.
 * Adapted from TDD source: OfficialVerificationPromptQualityScorecard.
 *
 * Input is SealedEvidencePackage (not OfficialVerificationPromptTraceSnapshot).
 * Checks are the same validation rules from the TDD harness,
 * adapted for sealed evidence (no expected-value comparison, replaced with presence/validity checks).
 */
@Slf4j
@RequiredArgsConstructor
public class SealedEvidencePromptScorecard {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private final ObjectMapper objectMapper;

    /**
     * Single-package evaluation matching harness evaluateRound() checks.
     * Harness checks requiring expected-value comparison are adapted to presence/validity checks.
     */
    public ScorecardResult evaluate(SealedEvidencePackage pkg) {
        List<ScorecardCheckResult> checks = new ArrayList<>();

        Map<String, Object> requestFacts = parseJson(pkg.getRequestFactsJson());
        Map<String, Object> authState = parseJson(pkg.getAuthStateJson());
        Map<String, Object> decision = parseJson(pkg.getDecisionJson());
        Map<String, Object> canonical = parseJson(pkg.getCanonicalContextJson());
        Map<String, Object> baseline = parseJson(pkg.getBaselineSnapshotJson());
        String systemPrompt = pkg.getSystemPromptText();
        String userPrompt = pkg.getUserPromptText();

        // --- Harness: request chain correlation ---
        check(checks, "correlationId is present",
                pkg.getCorrelationId() != null && !pkg.getCorrelationId().isBlank(),
                "correlationId=" + pkg.getCorrelationId());

        check(checks, "userId is present",
                pkg.getUserId() != null && !pkg.getUserId().isBlank(),
                "userId=" + pkg.getUserId());

        // --- Harness: event integrity (requestPath, clientIp, userAgent, httpMethod) ---
        check(checks, "requestPath is present",
                hasText(requestFacts, "requestPath"),
                "requestPath=" + text(requestFacts, "requestPath"));

        check(checks, "clientIp is present",
                hasText(requestFacts, "clientIp"),
                "clientIp=" + text(requestFacts, "clientIp"));

        check(checks, "userAgent is present",
                hasText(requestFacts, "userAgent"),
                "userAgent=" + text(requestFacts, "userAgent"));

        check(checks, "httpMethod is present",
                hasText(requestFacts, "httpMethod"),
                "httpMethod=" + text(requestFacts, "httpMethod"));

        // --- Harness: security attribute checks ---
        check(checks, "mfaVerified is true",
                "true".equals(String.valueOf(authState.get("mfaVerified"))),
                "mfaVerified=" + authState.get("mfaVerified"));

        check(checks, "authMethod is present",
                hasText(authState, "authMethod"),
                "authMethod=" + text(authState, "authMethod"));

        check(checks, "resourceSensitivity is present",
                hasText(requestFacts, "resourceSensitivity"),
                "resourceSensitivity=" + text(requestFacts, "resourceSensitivity"));

        check(checks, "isSensitiveResource is present",
                requestFacts.containsKey("isSensitiveResource"),
                "isSensitiveResource=" + requestFacts.get("isSensitiveResource"));

        check(checks, "authorizationEffect is present",
                hasText(authState, "authorizationEffect"),
                "authorizationEffect=" + text(authState, "authorizationEffect"));

        check(checks, "authorizationEffect is not UNKNOWN",
                hasText(authState, "authorizationEffect")
                        && !"UNKNOWN".equalsIgnoreCase(text(authState, "authorizationEffect")),
                "authorizationEffect=" + text(authState, "authorizationEffect"));

        check(checks, "effectiveRoles is present",
                authState.get("effectiveRoles") != null,
                "effectiveRoles=" + authState.get("effectiveRoles"));

        check(checks, "effectivePermissions is present",
                authState.get("effectivePermissions") != null,
                "effectivePermissions=" + authState.get("effectivePermissions"));

        check(checks, "recentRequestCount >= 1",
                asInt(requestFacts.get("recentRequestCount")) >= 1,
                "recentRequestCount=" + requestFacts.get("recentRequestCount"));

        // --- Harness: session/behavior novelty flags ---
        check(checks, "isNewSession flag is present",
                baseline.containsKey("isNewSession"),
                "isNewSession=" + baseline.get("isNewSession"));

        check(checks, "isNewDevice flag is present",
                baseline.containsKey("isNewDevice"),
                "isNewDevice=" + baseline.get("isNewDevice"));

        check(checks, "isNewUser flag is present",
                baseline.containsKey("isNewUser"),
                "isNewUser=" + baseline.get("isNewUser"));

        // --- Harness: sessionCtx checks (from canonicalContext.Session) ---
        Map<String, Object> sessionSection = extractSection(canonical, "session");
        check(checks, "sessionCtx.authMethod is present",
                hasText(sessionSection, "authMethod"),
                "sessionCtx.authMethod=" + text(sessionSection, "authMethod"));

        // --- Harness: behaviorCtx checks (from canonicalContext) ---
        Map<String, Object> observedScope = extractSection(canonical, "observedScope");
        check(checks, "behaviorCtx.currentUserAgentOS is present",
                hasText(observedScope, "currentUserAgentOS"),
                "observedScope.currentUserAgentOS=" + text(observedScope, "currentUserAgentOS"));

        check(checks, "behaviorCtx.currentUserAgentBrowser is present",
                hasText(observedScope, "currentUserAgentBrowser"),
                "observedScope.currentUserAgentBrowser=" + text(observedScope, "currentUserAgentBrowser"));

        // --- Harness: relatedDocuments check ---
        Map<String, Object> ragResults = parseJson(pkg.getRagResultsJson());
        check(checks, "ragResults is captured",
                pkg.getRagResultsJson() != null && !pkg.getRagResultsJson().isBlank(),
                "ragResults present");

        // --- Harness: canonical context and baseline ---
        check(checks, "canonicalContext is captured",
                pkg.getCanonicalContextJson() != null && !pkg.getCanonicalContextJson().isBlank(),
                "canonicalContextJson length=" + (pkg.getCanonicalContextJson() != null ? pkg.getCanonicalContextJson().length() : 0));

        check(checks, "baseline snapshot is captured",
                pkg.getBaselineSnapshotJson() != null && !pkg.getBaselineSnapshotJson().isBlank(),
                "baselineSnapshot present");

        // --- Harness: systemPrompt structural checks ---
        check(checks, "systemPrompt is captured",
                systemPrompt != null && !systemPrompt.isBlank(),
                "systemPrompt length=" + (systemPrompt != null ? systemPrompt.length() : 0));

        check(checks, "systemPrompt contains Zero Trust analyst instruction",
                systemPrompt != null && systemPrompt.contains("Zero Trust"),
                "systemPrompt contains 'Zero Trust': " + (systemPrompt != null && systemPrompt.contains("Zero Trust")));

        check(checks, "systemPrompt contains DECISION section",
                systemPrompt != null && systemPrompt.contains("=== DECISION ==="),
                "DECISION section present");

        check(checks, "systemPrompt contains output_format",
                systemPrompt != null && systemPrompt.contains("<output_format>"),
                "output_format section present");

        check(checks, "systemPrompt contains action schema",
                systemPrompt != null && systemPrompt.contains("\"action\":\"ALLOW|CHALLENGE|ESCALATE|BLOCK\""),
                "action schema present");

        // --- Harness: userPrompt section checks (individual, not combined) ---
        check(checks, "userPrompt is captured",
                userPrompt != null && !userPrompt.isBlank(),
                "userPrompt length=" + (userPrompt != null ? userPrompt.length() : 0));

        check(checks, "userPrompt contains CURRENT REQUEST AND EVENT section",
                userPrompt != null && userPrompt.contains("=== CURRENT REQUEST"),
                "CURRENT REQUEST section present");

        check(checks, "userPrompt contains BRIDGE RESOLUTION CONTEXT section",
                userPrompt != null && userPrompt.contains("=== BRIDGE RESOLUTION CONTEXT"),
                "BRIDGE RESOLUTION section present");

        check(checks, "userPrompt contains CONTEXT COVERAGE section",
                userPrompt != null && userPrompt.contains("=== CONTEXT COVERAGE"),
                "CONTEXT COVERAGE section present");

        check(checks, "userPrompt contains IDENTITY AND ROLE CONTEXT section",
                userPrompt != null && userPrompt.contains("=== IDENTITY AND ROLE"),
                "IDENTITY AND ROLE section present");

        check(checks, "userPrompt contains AUTHENTICATION AND ASSURANCE CONTEXT section",
                userPrompt != null && userPrompt.contains("=== AUTHENTICATION AND ASSURANCE"),
                "AUTHENTICATION AND ASSURANCE section present");

        check(checks, "userPrompt contains RESOURCE AND ACTION CONTEXT section",
                userPrompt != null && userPrompt.contains("=== RESOURCE AND ACTION"),
                "RESOURCE AND ACTION section present");

        check(checks, "userPrompt contains SESSION NARRATIVE CONTEXT section",
                userPrompt != null && userPrompt.contains("=== SESSION NARRATIVE"),
                "SESSION NARRATIVE section present");

        check(checks, "userPrompt contains PERSONAL WORK PROFILE section",
                userPrompt != null && userPrompt.contains("=== PERSONAL WORK PROFILE"),
                "PERSONAL WORK PROFILE section present");

        check(checks, "userPrompt contains ROLE AND WORK SCOPE CONTEXT section",
                userPrompt != null && userPrompt.contains("=== ROLE AND WORK SCOPE"),
                "ROLE AND WORK SCOPE section present");

        check(checks, "userPrompt contains EXPLICIT MISSING KNOWLEDGE section",
                userPrompt != null && userPrompt.contains("=== EXPLICIT MISSING KNOWLEDGE"),
                "EXPLICIT MISSING KNOWLEDGE section present");

        // --- Harness: additional userPrompt sections (sealed evidence extensions) ---
        check(checks, "userPrompt contains FRICTION AND APPROVAL section",
                userPrompt != null && userPrompt.contains("=== FRICTION AND APPROVAL"),
                "FRICTION AND APPROVAL section present");

        check(checks, "userPrompt contains DELEGATED OBJECTIVE section",
                userPrompt != null && userPrompt.contains("=== DELEGATED OBJECTIVE"),
                "DELEGATED OBJECTIVE section present");

        check(checks, "userPrompt contains OUTCOME AND REASONING MEMORY section",
                userPrompt != null && userPrompt.contains("=== OUTCOME AND REASONING MEMORY"),
                "REASONING MEMORY section present");

        // --- Harness: userPrompt evidence value checks ---
        String requestPath = text(requestFacts, "requestPath");
        check(checks, "userPrompt contains requestPath value",
                userPrompt != null && requestPath != null && userPrompt.contains(requestPath),
                "requestPath in userPrompt");

        String clientIp = text(requestFacts, "clientIp");
        check(checks, "userPrompt contains clientIp value",
                userPrompt != null && clientIp != null && userPrompt.contains(clientIp),
                "clientIp in userPrompt");

        check(checks, "userPrompt contains MfaVerified evidence",
                userPrompt != null && userPrompt.contains("MfaVerified"),
                "MfaVerified in userPrompt");

        check(checks, "userPrompt contains Sensitivity evidence",
                userPrompt != null && userPrompt.contains("Sensitivity:"),
                "Sensitivity in userPrompt");

        check(checks, "userPrompt contains AuthorizationEffect: ALLOW",
                userPrompt != null && userPrompt.contains("AuthorizationEffect: ALLOW"),
                "AuthorizationEffect: ALLOW in userPrompt");

        check(checks, "userPrompt contains NewUser evidence",
                userPrompt != null && userPrompt.contains("NewUser:"),
                "NewUser in userPrompt");

        // --- Harness: userPrompt noise path exclusion ---
        check(checks, "userPrompt does not contain status/SSE/evidence noise paths",
                userPrompt == null || (!userPrompt.contains("/admin/api/test-action/status")
                        && !userPrompt.contains("/admin/api/sse/llm-analysis/user")
                        && !userPrompt.contains("/admin/api/enterprise/verification/context/eir/runs/")),
                "userPrompt noise path check");

        // --- Harness: raw prompt checks ---
        check(checks, "rawSystemPrompt is captured",
                pkg.getRawSystemPrompt() != null && !pkg.getRawSystemPrompt().isBlank(),
                "rawSystemPrompt length=" + (pkg.getRawSystemPrompt() != null ? pkg.getRawSystemPrompt().length() : 0));

        check(checks, "rawUserPrompt is captured",
                pkg.getRawUserPrompt() != null && !pkg.getRawUserPrompt().isBlank(),
                "rawUserPrompt length=" + (pkg.getRawUserPrompt() != null ? pkg.getRawUserPrompt().length() : 0));

        check(checks, "promptHash is captured",
                pkg.getPromptHash() != null && !pkg.getPromptHash().isBlank(),
                "promptHash=" + pkg.getPromptHash());

        // --- Harness: promptExecutionMetadata and governance checks ---
        check(checks, "promptExecutionMetadata is captured",
                pkg.getPromptExecutionMetadataJson() != null && !pkg.getPromptExecutionMetadataJson().isBlank(),
                "promptExecutionMetadata present");

        Map<String, Object> promptExecMeta = parseJson(pkg.getPromptExecutionMetadataJson());
        Map<String, Object> governance = promptExecMeta.get("governanceDescriptor") instanceof Map<?,?> gm
                ? castToStringObjectMap(gm) : Map.of();

        check(checks, "promptExecutionMetadata.promptKey is cortex.security-decision",
                "cortex.security-decision".equals(text(governance, "promptKey")),
                "promptKey=" + text(governance, "promptKey"));

        check(checks, "promptExecutionMetadata.templateKey is SecurityDecisionStandard",
                "SecurityDecisionStandard".equals(text(governance, "templateKey")),
                "templateKey=" + text(governance, "templateKey"));

        check(checks, "promptExecutionMetadata.promptEvidenceCompleteness is present",
                hasText(promptExecMeta, "promptEvidenceCompleteness"),
                "promptEvidenceCompleteness=" + text(promptExecMeta, "promptEvidenceCompleteness"));

        check(checks, "metadata.promptVersion is present",
                hasText(promptExecMeta, "promptVersion"),
                "promptVersion=" + text(promptExecMeta, "promptVersion"));

        check(checks, "metadata.promptHash/systemPromptHash/userPromptHash are present",
                hasText(promptExecMeta, "promptHash")
                        && hasText(promptExecMeta, "systemPromptHash")
                        && hasText(promptExecMeta, "userPromptHash"),
                "prompt hashes present");

        // --- Sealed evidence: decision checks ---
        check(checks, "decision action is present",
                hasText(decision, "action"),
                "action=" + text(decision, "action"));

        check(checks, "decision reasoning is diagnostic when supplied",
                true,
                "reasoning length=" + (text(decision, "reasoning") != null ? text(decision, "reasoning").length() : 0));

        check(checks, "decision processingPath is present",
                hasText(decision, "processingPath"),
                "processingPath=" + text(decision, "processingPath"));

        check(checks, "decision confidence audit value is bounded when supplied",
                unitIntervalIfPresent(decision.get("confidence")),
                "confidence=" + decision.get("confidence"));

        // --- Sealed evidence: package integrity ---
        check(checks, "package is sealed",
                pkg.isSealed(),
                "sealed=" + pkg.isSealed());

        check(checks, "packageHash is present",
                pkg.getPackageHash() != null && !pkg.getPackageHash().isBlank(),
                "packageHash=" + pkg.getPackageHash());

        check(checks, "expiresAt is set",
                pkg.getExpiresAt() != null,
                "expiresAt=" + pkg.getExpiresAt());

        // --- Optional: contextBindingHash ---
        if (hasText(requestFacts, "contextBindingHash")) {
            check(checks, "contextBindingHash is present",
                    true, "contextBindingHash=" + text(requestFacts, "contextBindingHash"));
        }

        check(checks, "authorizationEffectProvenance is present",
                hasText(authState, "authorizationEffectProvenance"),
                "authorizationEffectProvenance=" + text(authState, "authorizationEffectProvenance"));

        return ScorecardResult.of("SealedEvidence-" + pkg.getPackageId(), checks);
    }

    /**
     * Multi-round progression evaluation matching harness evaluateProgression() checks.
     * Requires at least 3 sealed evidence packages from the same user in chronological order.
     */
    public ScorecardResult evaluateProgression(List<SealedEvidencePackage> rounds) {
        if (rounds == null || rounds.size() < 3) {
            return ScorecardResult.of("Progression-INSUFFICIENT", List.of(
                    new ScorecardCheckResult("at least 3 rounds required", false,
                            "rounds=" + (rounds != null ? rounds.size() : 0))));
        }

        List<ScorecardCheckResult> checks = new ArrayList<>();

        int firstDocs = countRagDocuments(rounds.get(0));
        int secondDocs = countRagDocuments(rounds.get(1));
        int thirdDocs = countRagDocuments(rounds.get(2));

        check(checks,
                "relatedDocuments accumulate 0->1->2 across rounds",
                firstDocs == 0 && secondDocs == 1 && thirdDocs == 2,
                "docs progression=" + firstDocs + " -> " + secondDocs + " -> " + thirdDocs);

        check(checks,
                "relatedDocuments never regress across rounds",
                firstDocs <= secondDocs && secondDocs <= thirdDocs,
                "docs progression=" + firstDocs + " -> " + secondDocs + " -> " + thirdDocs);

        String firstUserPrompt = rounds.get(0).getUserPromptText();
        String secondUserPrompt = rounds.get(1).getUserPromptText();
        String thirdUserPrompt = rounds.get(2).getUserPromptText();

        check(checks,
                "1st round userPrompt shows baseline deficiency or PROVISIONAL",
                containsAny(firstUserPrompt,
                        "No baseline established",
                        "Personal behavioral baseline is not established yet.",
                        "PROVISIONAL"),
                "firstRound baseline language");

        check(checks,
                "2nd round userPrompt contains OBSERVED WORK PATTERN CONTEXT",
                contains(secondUserPrompt, "=== OBSERVED WORK PATTERN CONTEXT ==="),
                "secondRound observed work pattern");

        check(checks,
                "3rd round userPrompt has more work profile observations than 2nd",
                extractWorkProfileObservationCount(thirdUserPrompt)
                        > extractWorkProfileObservationCount(secondUserPrompt),
                "2nd observations=" + extractWorkProfileObservationCount(secondUserPrompt)
                        + ", 3rd observations=" + extractWorkProfileObservationCount(thirdUserPrompt));

        check(checks,
                "3rd round userPrompt preserves core security facts",
                contains(thirdUserPrompt, "MfaVerified: true")
                        && contains(thirdUserPrompt, "AuthorizationEffect: ALLOW"),
                "3rd round core security facts");

        // Per-round progression checks (rounds 2+)
        for (int i = 1; i < rounds.size(); i++) {
            String currentPrompt = rounds.get(i).getUserPromptText();
            int prevDocs = countRagDocuments(rounds.get(i - 1));
            int currDocs = countRagDocuments(rounds.get(i));

            check(checks,
                    "round " + (i + 1) + " relatedDocuments >= previous round",
                    currDocs >= prevDocs,
                    "round " + i + " docs=" + prevDocs + ", round " + (i + 1) + " docs=" + currDocs);

            check(checks,
                    "round " + (i + 1) + " userPrompt preserves MfaVerified: true",
                    contains(currentPrompt, "MfaVerified: true"),
                    "round " + (i + 1) + " MfaVerified");

            check(checks,
                    "round " + (i + 1) + " userPrompt preserves AuthorizationEffect: ALLOW",
                    contains(currentPrompt, "AuthorizationEffect: ALLOW"),
                    "round " + (i + 1) + " AuthorizationEffect");

            if (i >= 1) {
                check(checks,
                        "round " + (i + 1) + " userPrompt contains OBSERVED WORK PATTERN CONTEXT",
                        contains(currentPrompt, "=== OBSERVED WORK PATTERN CONTEXT ==="),
                        "round " + (i + 1) + " observed work pattern");
            }

            if (i >= 2) {
                int prevObs = extractWorkProfileObservationCount(rounds.get(i - 1).getUserPromptText());
                int currObs = extractWorkProfileObservationCount(currentPrompt);
                check(checks,
                        "round " + (i + 1) + " work profile observation count does not regress",
                        currObs >= prevObs,
                        "round " + i + " observations=" + prevObs + ", round " + (i + 1) + " observations=" + currObs);
            }
        }

        return ScorecardResult.of("Progression-" + rounds.get(0).getUserId(), checks);
    }

    // --- Utility methods ---

    private void check(List<ScorecardCheckResult> checks, String label, boolean passed, String evidence) {
        checks.add(new ScorecardCheckResult(label, passed, evidence));
    }

    private boolean unitIntervalIfPresent(Object value) {
        if (value == null) return true;
        if (value instanceof Number number) {
            double numeric = number.doubleValue();
            return !Double.isNaN(numeric) && !Double.isInfinite(numeric) && numeric >= 0.0d && numeric <= 1.0d;
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                double numeric = Double.parseDouble(text.trim());
                return !Double.isNaN(numeric) && !Double.isInfinite(numeric) && numeric >= 0.0d && numeric <= 1.0d;
            }
            catch (NumberFormatException ignored) {
                return false;
            }
        }
        return false;
    }

    private boolean hasText(Map<String, Object> map, String key) {
        if (map == null) return false;
        Object value = map.get(key);
        return value instanceof String text && !text.isBlank();
    }

    private String text(Map<String, Object> map, String key) {
        if (map == null) return null;
        Object value = map.get(key);
        return value != null ? String.valueOf(value) : null;
    }

    private int asInt(Object value) {
        if (value instanceof Number number) return number.intValue();
        if (value instanceof String text && text.matches("-?\\d+")) return Integer.parseInt(text);
        return -1;
    }

    private boolean contains(String text, String expected) {
        return text != null && expected != null && !text.isBlank() && !expected.isBlank() && text.contains(expected);
    }

    private boolean containsAny(String text, String... candidates) {
        if (text == null || text.isBlank() || candidates == null) return false;
        for (String c : candidates) {
            if (c != null && !c.isBlank() && text.contains(c)) return true;
        }
        return false;
    }

    private int extractWorkProfileObservationCount(String userPrompt) {
        if (userPrompt == null || userPrompt.isBlank()) return -1;
        String marker = "WorkProfileSummary: Window 7d | Observations ";
        int start = userPrompt.indexOf(marker);
        if (start < 0) return -1;
        int numberStart = start + marker.length();
        int numberEnd = numberStart;
        while (numberEnd < userPrompt.length() && Character.isDigit(userPrompt.charAt(numberEnd))) {
            numberEnd++;
        }
        if (numberEnd <= numberStart) return -1;
        return Integer.parseInt(userPrompt.substring(numberStart, numberEnd));
    }

    private int countRagDocuments(SealedEvidencePackage pkg) {
        if (pkg.getRagResultsJson() == null || pkg.getRagResultsJson().isBlank()) return 0;
        Map<String, Object> rag = parseJson(pkg.getRagResultsJson());
        Object docs = rag.get("relatedDocuments");
        if (docs instanceof List<?> list) return list.size();
        Object count = rag.get("documentCount");
        if (count instanceof Number n) return n.intValue();
        return 0;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> extractSection(Map<String, Object> canonical, String sectionName) {
        if (canonical == null) return Map.of();
        Object section = canonical.get(sectionName);
        if (section instanceof Map<?,?> map) return castToStringObjectMap(map);
        return Map.of();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> castToStringObjectMap(Map<?, ?> raw) {
        Map<String, Object> result = new LinkedHashMap<>();
        raw.forEach((k, v) -> { if (k instanceof String sk) result.put(sk, v); });
        return result;
    }

    private Map<String, Object> parseJson(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, MAP_TYPE);
        } catch (Exception e) {
            log.error("[SealedEvidenceScorecard] Failed to parse JSON", e);
            return Map.of();
        }
    }
}

