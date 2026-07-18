package io.contexa.contexacore.verification.metric;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Converts raw official metric observations into operator-readable diagnostic evidence
 * before the result is persisted to the official verification ledger.
 */
public class OfficialPromptQualityNarrativeCatalog {

    public static final String CATALOG_VERSION = "PQA-OFFICIAL-DIAGNOSTIC-CATALOG-2026.05.11-ACTUAL-PROMPT-LEDGER";

    private static final Set<String> METRIC_CODES = Set.of(
            "EIR", "CCR", "CCSR", "PFR", "MTR", "COR",
            "RAP", "RPI", "BMA", "USNS", "BSR", "PRE");

    private final OfficialVerificationMessageResolver messages;

    public OfficialPromptQualityNarrativeCatalog() {
        this(OfficialVerificationMessageResolver.classpath(Locale.KOREAN));
    }

    public OfficialPromptQualityNarrativeCatalog(OfficialVerificationMessageResolver messages) {
        this.messages = Objects.requireNonNull(messages, "messages");
    }

    public Map<String, OfficialMetricEvaluationResult> enrichResults(
            Map<String, OfficialMetricEvaluationResult> rawResults,
            SealedEvidencePackage evidencePackage,
            String requestPath) {
        if (rawResults == null || rawResults.isEmpty()) {
            return Map.of();
        }
        Map<String, OfficialMetricEvaluationResult> enriched = new LinkedHashMap<>();
        rawResults.forEach((key, result) -> {
            if (result == null) {
                return;
            }
            String metricCode = normalize(result.metricCode());
            if (!StringUtils.hasText(metricCode)) {
                metricCode = normalize(key);
            }
            String finalMetricCode = metricCode;
            List<OfficialMetricCheckObservation> checks = result.checks() == null
                    ? List.of()
                    : result.checks().stream()
                    .map(check -> enrichCheck(finalMetricCode, check, evidencePackage, requestPath))
                    .toList();
            enriched.put(finalMetricCode, new OfficialMetricEvaluationResult(
                    finalMetricCode,
                    result.score(),
                    result.passedChecks(),
                    result.totalChecks(),
                    result.state(),
                    checks));
        });
        return Map.copyOf(enriched);
    }

    public String metricName(String metricCode) {
        return metric(metricCode).name();
    }

    public String metricPurpose(String metricCode) {
        return metric(metricCode).purpose();
    }

    public String metricImpact(String metricCode) {
        return metric(metricCode).impact();
    }

    public String metricDefaultAction(String metricCode) {
        return metric(metricCode).action();
    }

    public String metricDefaultReverify(String metricCode) {
        return metric(metricCode).reverify();
    }

    public static boolean hasPlainOperatorText(String value) {
        return StringUtils.hasText(value)
                && containsHangul(value)
                && !containsBrokenText(value)
                && !containsInternalOnlyText(value);
    }

    public static boolean containsBrokenText(String value) {
        if (value == null) {
            return false;
        }
        return value.indexOf(0xFFFD) >= 0
                || containsQuestionMarkBeforeHangul(value)
                || containsUnexpectedCjkScript(value);
    }

    public static boolean containsInternalOnlyText(String value) {
        if (value == null) {
            return false;
        }
        String text = value.trim();
        String lower = text.toLowerCase(Locale.ROOT);
        return lower.contains("core official sealed evidence metric")
                || lower.contains("threshold_failed")
                || lower.contains("required prompt evidence is missing")
                || lower.contains("finding-eir")
                || lower.contains("agg-source")
                || lower.contains("run-eir-source")
                || lower.contains("pkg-source")
                || lower.contains("cert-source")
                || lower.contains("case-source")
                || lower.contains("issue-eir")
                || lower.equals("success")
                || lower.equals("missing")
                || lower.equals("insufficient")
                || lower.equals("not_applicable")
                || lower.equals("present")
                || lower.equals("absent")
                || lower.equals("unknown")
                || lower.equals("blank")
                || lower.equals("mismatch")
                || lower.startsWith("sealedevidence.")
                || lower.startsWith("source");
    }

    private OfficialMetricCheckObservation enrichCheck(
            String metricCode,
            OfficialMetricCheckObservation check,
            SealedEvidencePackage evidencePackage,
            String requestPath) {
        if (check == null) {
            throw new IllegalStateException("Official metric narrative cannot enrich a null check. metricCode="
                    + metricCode);
        }
        MetricNarrative metric = metric(metricCode);
        CheckNarrative checkNarrative = checkNarrative(metricCode, check, metric);
        String subject = checkNarrative.subject();
        String generatedExpected = message("enterprise.pqa.officialNarrative.generated.expectedTpl",
                subject, operatorValue(check.expectedValue()));
        String generatedActual = check.passed()
                ? message("enterprise.pqa.officialNarrative.generated.actualPassedTpl",
                        subject, operatorValue(check.actualValue()))
                : message("enterprise.pqa.officialNarrative.generated.actualFailedTpl",
                        subject, operatorValue(check.actualValue()));
        String generatedLabel = check.passed()
                ? message("enterprise.pqa.officialNarrative.generated.labelPassedTpl", subject)
                : message("enterprise.pqa.officialNarrative.generated.labelFailedTpl", subject);
        String owner = checkNarrative.owner();
        String evidenceLocation = evidenceLocation(check.source(), requestPath);
        String generatedReason = check.passed()
                ? message("enterprise.pqa.officialNarrative.generated.reasonPassedTpl",
                        value(evidencePackage == null ? null : evidencePackage.getPackageId()),
                        metric.name(), evidenceLocation)
                : message("enterprise.pqa.officialNarrative.generated.reasonFailedTpl",
                        subject, checkNarrative.cause(), evidenceLocation, owner);
        String generatedNextAction = check.passed()
                ? message("enterprise.pqa.officialNarrative.generated.actionPassed")
                : message("enterprise.pqa.officialNarrative.generated.actionFailedTpl", checkNarrative.action());
        String generatedReverify = check.passed()
                ? message("enterprise.pqa.officialNarrative.generated.reverifyPassedTpl", subject)
                : message("enterprise.pqa.officialNarrative.generated.reverifyFailedTpl", checkNarrative.reverify());

        return new OfficialMetricCheckObservation(
                check.checkCode(),
                firstText(check.label(), generatedLabel),
                firstText(check.expectedValue(), generatedExpected),
                firstText(check.actualValue(), generatedActual),
                check.passed(),
                check.source(),
                check.passed() ? "INFO" : safe(check.severity(), "BLOCKING"),
                check.passed() ? "" : safe(check.failureType(), metricCode + "_CHECK_FAILED"),
                owner,
                firstText(check.operatorReason(), generatedReason),
                firstText(check.nextAction(), generatedNextAction),
                firstText(check.reverifyCriterion(), generatedReverify),
                check.issueKey(),
                check.customerVisible(),
                check.readinessScope(),
                check.purposeVersion(),
                check.inputReadinessState(),
                check.purposeResult(),
                check.detectedSignalsJson(),
                check.interpretationLinksJson(),
                check.decisionUtility(),
                check.whyItMatters());
    }

    private CheckNarrative checkNarrative(
            String metricCode,
            OfficialMetricCheckObservation check,
            MetricNarrative metric) {
        String code = normalize(check.checkCode());
        String source = normalize(check.source());
        if (source.contains("BASELINESNAPSHOT.COVERAGE") || code.contains("BMA_COVERAGE")) {
            return checkNarrative("baselineCoverage");
        }
        if (source.contains("BASELINESNAPSHOT.OBSERVATION") || code.contains("OBSERVATION_DAYS")) {
            return checkNarrative("baselineObservation");
        }
        if (source.contains("BASELINESNAPSHOT.EVENTCOUNT") || code.contains("EVENT_COUNT")) {
            return checkNarrative("baselineEventCount");
        }
        if (source.contains("BASELINESNAPSHOT.FALLBACK") || code.contains("FALLBACK")) {
            return checkNarrative("baselineFallback");
        }
        if (source.contains("BASELINESNAPSHOT.PROVISIONAL") || code.contains("PROVISIONAL")) {
            return checkNarrative("baselineProvisional");
        }
        if (source.contains("BASELINESNAPSHOT.MATURITY") || code.contains("MATURITY") || source.equals("SEALEDEVIDENCE.BASELINESNAPSHOT")) {
            return checkNarrative("baselineMaturity");
        }
        if (source.contains("RAGRESULTS") || source.contains("RELATEDDOCUMENTS") || code.contains("RAP_DOC")) {
            return checkNarrative("ragAuthorization");
        }
        if (source.contains("PROMPTEXECUTIONMETADATA.PROMPTCONTRACTVIOLATIONCOUNT") || code.contains("CONTRACT")) {
            return checkNarrative("promptContract");
        }
        if (source.contains("PROMPTEXECUTIONMETADATA") && (code.contains("BUDGET") || source.contains("TOKEN"))) {
            return checkNarrative("promptBudget");
        }
        if (source.contains("CANONICALCONTEXT.FRICTIONPROFILE") || code.contains("FRICTION")) {
            return checkNarrative("behaviorFriction");
        }
        if (source.contains("CANONICALCONTEXT.BEHAVIORALSURPRISE") || code.contains("SURPRISE")) {
            return checkNarrative("behaviorSurprise");
        }
        if (code.contains("EXPLICIT_MISSING_KNOWLEDGE")) {
            return checkNarrative("missingKnowledge");
        }
        if (code.contains("UNCERTAINTY_MARKER")) {
            return checkNarrative("uncertainty");
        }
        if (code.contains("PROVISIONAL_MARKER")) {
            return checkNarrative("provisionalEvidence");
        }
        String subject = subject(metricCode, check.checkCode(), check.label(), check.source());
        return new CheckNarrative(
                subject,
                ownerName(check.remediationOwner()),
                failureMeaning(check.failureType(), metric),
                message("enterprise.pqa.officialNarrative.check.default.actionTpl",
                        ownerName(check.remediationOwner()), subject),
                message("enterprise.pqa.officialNarrative.check.default.reverifyTpl",
                        subject, metric.reverify()));
    }

    private CheckNarrative checkNarrative(String key) {
        String prefix = "enterprise.pqa.officialNarrative.check." + key + ".";
        return new CheckNarrative(
                message(prefix + "subject"),
                message(prefix + "owner"),
                message(prefix + "cause"),
                message(prefix + "action"),
                message(prefix + "reverify"));
    }

    private MetricNarrative metric(String metricCode) {
        String normalized = normalize(metricCode);
        String key = METRIC_CODES.contains(normalized) ? normalized.toLowerCase(Locale.ROOT) : "default";
        String prefix = "enterprise.pqa.officialNarrative.metric." + key + ".";
        return new MetricNarrative(
                message(prefix + "name"),
                message(prefix + "purpose"),
                message(prefix + "impact"),
                message(prefix + "action"),
                message(prefix + "reverify"));
    }

    private String subject(String metricCode, String checkCode, String fallback, String source) {
        String code = normalize(checkCode);
        String sourceText = normalize(source);
        if (sourceText.contains("BASELINESNAPSHOT") || code.startsWith("BMA_")) {
            if (sourceText.contains("COVERAGE") || code.contains("COVERAGE")) return message("enterprise.pqa.officialNarrative.subject.baselineCoverage");
            if (sourceText.contains("OBSERVATION") || code.contains("OBSERVATION_DAYS")) return message("enterprise.pqa.officialNarrative.subject.baselineObservation");
            if (sourceText.contains("EVENTCOUNT") || code.contains("EVENT_COUNT")) return message("enterprise.pqa.officialNarrative.subject.baselineEventCount");
            if (sourceText.contains("FALLBACK") || code.contains("FALLBACK")) return message("enterprise.pqa.officialNarrative.subject.baselineFallback");
            if (sourceText.contains("PROVISIONAL") || code.contains("PROVISIONAL")) return message("enterprise.pqa.officialNarrative.subject.baselineProvisional");
            return message("enterprise.pqa.officialNarrative.subject.baselineMaturity");
        }
        if (sourceText.contains("RAGRESULTS") || sourceText.contains("RELATEDDOCUMENTS")) {
            return message("enterprise.pqa.officialNarrative.subject.ragAuthorization");
        }
        if (code.contains("MFA")) return message("enterprise.pqa.officialNarrative.subject.mfa");
        if (code.contains("AUTHORIZATION_EFFECT")) return message("enterprise.pqa.officialNarrative.subject.authorizationEffect");
        if (code.contains("AUTH_METHOD")) return message("enterprise.pqa.officialNarrative.subject.authMethod");
        if (code.contains("EFFECTIVE_ROLE")) return message("enterprise.pqa.officialNarrative.subject.effectiveRole");
        if (code.contains("TENANT")) return message("enterprise.pqa.officialNarrative.subject.tenant");
        if (code.contains("FINAL_USER_PROMPT_NOT_COMPACTED") || code.contains("FINAL_PROMPT_COMPACTED")) {
            return message("enterprise.pqa.officialNarrative.subject.compactionMarker");
        }
        if (code.contains("FINAL_USER_PROMPT_NO_TRUNCATED_FACT_PLACEHOLDER")
                || code.contains("FINAL_PROMPT_TRUNCATED_FACT")) {
            return message("enterprise.pqa.officialNarrative.subject.truncatedFact");
        }
        if (code.contains("USER_PROMPT_HAS_DECISION_CONTEXT")) return message("enterprise.pqa.officialNarrative.subject.decisionContext");
        if (code.contains("USER") && !code.contains("NEW_USER")) return message("enterprise.pqa.officialNarrative.subject.user");
        if (code.contains("CLIENT_IP")) return message("enterprise.pqa.officialNarrative.subject.clientIp");
        if (code.contains("HTTP_METHOD")) return message("enterprise.pqa.officialNarrative.subject.httpMethod");
        if (code.contains("REQUEST_PATH")) return message("enterprise.pqa.officialNarrative.subject.requestPath");
        if (code.contains("RESOURCE_ID") || code.contains("ACTUAL_RESOURCE")) return message("enterprise.pqa.officialNarrative.subject.resourceId");
        if (code.contains("URL_TEMPLATE")) return message("enterprise.pqa.officialNarrative.subject.urlTemplate");
        if (code.contains("PROMPT_HASH")) return message("enterprise.pqa.officialNarrative.subject.promptHash");
        if (code.contains("SYSTEM_PROMPT")) return message("enterprise.pqa.officialNarrative.subject.systemPrompt");
        if (code.contains("USER_PROMPT")) return message("enterprise.pqa.officialNarrative.subject.userPrompt");
        if (code.contains("CONTEXT_HASH")) return message("enterprise.pqa.officialNarrative.subject.contextHash");
        if (code.contains("PACKAGE_HASH") || code.contains("PACKAGE_ID")) return message("enterprise.pqa.officialNarrative.subject.package");
        if (code.contains("CONTRACT")) return message("enterprise.pqa.officialNarrative.subject.contract");
        if (code.contains("BUDGET")) return message("enterprise.pqa.officialNarrative.subject.budget");
        if (code.contains("RAW_TRUTH")) return message("enterprise.pqa.officialNarrative.subject.rawTruth");
        if (code.contains("COMPRESSION")) return message("enterprise.pqa.officialNarrative.subject.compression");
        if (code.contains("BASELINE") || code.contains("MATURITY") || code.contains("OBSERVATION") || code.contains("FALLBACK")) return message("enterprise.pqa.officialNarrative.subject.learningBaseline");
        if (code.contains("RAG") || code.contains("DOCUMENT") || code.contains("DOC_")) return message("enterprise.pqa.officialNarrative.subject.ragAuthorization");
        if (code.contains("NOVELTY") || code.contains("TIME") || code.contains("NETWORK")
                || code.contains("BROWSER") || code.contains("DEVICE") || code.contains("REQUEST_COMBINATION")) {
            return message("enterprise.pqa.officialNarrative.subject.userNovelty");
        }
        if (code.contains("FRICTION") || code.contains("SURPRISE") || code.contains("SESSION_NARRATIVE")) return message("enterprise.pqa.officialNarrative.subject.behavior");
        if (code.contains("PROTECTABLE") || code.contains("VERIFICATION_REQUIRED")) return message("enterprise.pqa.officialNarrative.subject.protectable");
        if (StringUtils.hasText(fallback) && !containsBrokenText(fallback) && containsHangul(fallback)) {
            return fallback.trim();
        }
        return metric(metricCode).name() + message("enterprise.pqa.officialNarrative.subject.checkSuffix");
    }

    private String failureMeaning(String failureType, MetricNarrative metric) {
        String type = normalize(failureType);
        if (type.contains("MISSING")) {
            return message("enterprise.pqa.officialNarrative.failure.missing");
        }
        if (type.contains("MISMATCH")) {
            return message("enterprise.pqa.officialNarrative.failure.mismatch");
        }
        if (type.contains("CONTAMINATION") || type.contains("FOREIGN") || type.contains("UNAUTHORIZED")) {
            return message("enterprise.pqa.officialNarrative.failure.contamination");
        }
        if (type.contains("OVERCLAIMED") || type.contains("INSUFFICIENT")) {
            return message("enterprise.pqa.officialNarrative.failure.overclaimed");
        }
        if (type.contains("BLOCKER") || type.contains("VIOLATION")) {
            return message("enterprise.pqa.officialNarrative.failure.blocker");
        }
        return metric.purpose();
    }

    private String ownerName(String owner) {
        String normalized = normalize(owner);
        if (normalized.contains("PROMPT_ASSEMBLER")) return message("enterprise.pqa.officialNarrative.owner.promptAssembler");
        if (normalized.contains("REQUEST_CONTEXT")) return message("enterprise.pqa.officialNarrative.owner.requestContext");
        if (normalized.contains("AUTH_CONTEXT")) return message("enterprise.pqa.officialNarrative.owner.authContext");
        if (normalized.contains("CONTEXT_ASSEMBLER")) return message("enterprise.pqa.officialNarrative.owner.contextAssembler");
        if (normalized.contains("PROMPT_CAPTURE")) return message("enterprise.pqa.officialNarrative.owner.promptCapture");
        if (normalized.contains("PROMPT_TEMPLATE")) return message("enterprise.pqa.officialNarrative.owner.promptTemplate");
        if (normalized.contains("PROMPT_GOVERNANCE")) return message("enterprise.pqa.officialNarrative.owner.promptGovernance");
        if (normalized.contains("EVIDENCE")) return message("enterprise.pqa.officialNarrative.owner.evidence");
        if (normalized.contains("RAG")) return message("enterprise.pqa.officialNarrative.owner.rag");
        if (normalized.contains("LEARNING") || normalized.contains("BASELINE")) return message("enterprise.pqa.officialNarrative.owner.learningBaseline");
        if (normalized.contains("BEHAVIOR")) return message("enterprise.pqa.officialNarrative.owner.behavior");
        if (normalized.contains("PROTECTABLE")) return message("enterprise.pqa.officialNarrative.owner.protectable");
        if (normalized.contains("OFFICIAL_LEDGER")) return message("enterprise.pqa.officialNarrative.owner.officialLedger");
        if (!StringUtils.hasText(owner)) return message("enterprise.pqa.officialNarrative.owner.official");
        return owner.trim();
    }

    private String operatorValue(String value) {
        if (!StringUtils.hasText(value)) {
            return message("enterprise.pqa.officialNarrative.value.none");
        }
        String trimmed = value.trim();
        String lower = trimmed.toLowerCase(Locale.ROOT);
        if (lower.contains("coverage values")) return message("enterprise.pqa.officialNarrative.value.coverageStored");
        if (lower.contains("observationdays")) return message("enterprise.pqa.officialNarrative.value.observationStored");
        if (lower.contains("eventcount")) return message("enterprise.pqa.officialNarrative.value.eventCountStored");
        if (lower.contains("fallbackratio")) return message("enterprise.pqa.officialNarrative.value.fallbackStored");
        if (lower.contains("authorizationdecision")) return message("enterprise.pqa.officialNarrative.value.authorizationStored");
        if (lower.contains("permissionscope")) return message("enterprise.pqa.officialNarrative.value.permissionScopeStored");
        return switch (lower) {
            case "present" -> message("enterprise.pqa.officialNarrative.value.present");
            case "missing" -> message("enterprise.pqa.officialNarrative.value.missing");
            case "absent" -> message("enterprise.pqa.officialNarrative.value.missing");
            case "blank" -> message("enterprise.pqa.officialNarrative.value.blank");
            case "unknown" -> message("enterprise.pqa.officialNarrative.value.unknown");
            case "true" -> message("enterprise.pqa.officialNarrative.value.true");
            case "false" -> message("enterprise.pqa.officialNarrative.value.false");
            case "success" -> message("enterprise.pqa.officialNarrative.value.success");
            case "threshold_failed" -> message("enterprise.pqa.officialNarrative.value.thresholdFailed");
            case "mismatch" -> message("enterprise.pqa.officialNarrative.value.mismatch");
            case "not_applicable" -> message("enterprise.pqa.officialNarrative.value.notApplicable");
            case "insufficient" -> message("enterprise.pqa.officialNarrative.value.insufficient");
            default -> trimmed;
        };
    }

    private String evidenceLocation(String source, String requestPath) {
        if (StringUtils.hasText(source)) {
            String normalized = normalize(source);
            if (normalized.contains("BASELINESNAPSHOT.COVERAGE")) return message("enterprise.pqa.officialNarrative.location.baselineCoverage");
            if (normalized.contains("BASELINESNAPSHOT.OBSERVATION")) return message("enterprise.pqa.officialNarrative.location.baselineObservation");
            if (normalized.contains("BASELINESNAPSHOT.EVENTCOUNT")) return message("enterprise.pqa.officialNarrative.location.baselineEventCount");
            if (normalized.contains("BASELINESNAPSHOT.FALLBACK")) return message("enterprise.pqa.officialNarrative.location.baselineFallback");
            if (normalized.contains("BASELINESNAPSHOT.PROVISIONAL")) return message("enterprise.pqa.officialNarrative.location.baselineProvisional");
            if (normalized.contains("BASELINESNAPSHOT")) return message("enterprise.pqa.officialNarrative.location.baseline");
            if (normalized.contains("RAGRESULTS") || normalized.contains("RELATEDDOCUMENTS")) return message("enterprise.pqa.officialNarrative.location.rag");
            if (normalized.contains("AUTHSTATE")) return message("enterprise.pqa.officialNarrative.location.authState");
            if (normalized.contains("REQUESTFACTS")) return message("enterprise.pqa.officialNarrative.location.requestFacts");
            if (normalized.contains("PROMPTEXECUTIONMETADATA")) return message("enterprise.pqa.officialNarrative.location.promptMetadata");
            if (normalized.contains("USERPROMPTTEXT") || normalized.contains("SYSTEMPROMPTTEXT")) return message("enterprise.pqa.officialNarrative.location.promptCapture");
            if (normalized.contains("PROTECTABLERESOURCE") || normalized.contains("RESOURCE")) return message("enterprise.pqa.officialNarrative.location.protectable");
            return message("enterprise.pqa.officialNarrative.location.sealedEvidence");
        }
        if (StringUtils.hasText(requestPath)) {
            return message("enterprise.pqa.officialNarrative.location.requestPathPrefix", requestPath.trim());
        }
        return message("enterprise.pqa.officialNarrative.location.sealedEvidence");
    }

    private static boolean containsHangul(String value) {
        if (value == null) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            if (isHangul(value.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsUnexpectedCjkScript(String value) {
        for (int i = 0; i < value.length(); i++) {
            Character.UnicodeScript script = Character.UnicodeScript.of(value.charAt(i));
            if (script == Character.UnicodeScript.HAN
                    || script == Character.UnicodeScript.HIRAGANA
                    || script == Character.UnicodeScript.KATAKANA) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsQuestionMarkBeforeHangul(String value) {
        for (int i = 0; i < value.length() - 1; i++) {
            if (value.charAt(i) == '?' && isHangul(value.charAt(i + 1))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isHangul(char ch) {
        return ch >= 0xAC00 && ch <= 0xD7A3;
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private String firstText(String value, String fallback) {
        return hasPlainOperatorText(value) ? value.trim() : fallback;
    }

    private String safe(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    private String value(String value) {
        return StringUtils.hasText(value) ? value.trim() : message("enterprise.pqa.officialNarrative.value.unknown");
    }

    private String message(String key, Object... arguments) {
        return messages.resolve(key, arguments);
    }

    private record MetricNarrative(
            String name,
            String purpose,
            String impact,
            String action,
            String reverify) {
    }

    private record CheckNarrative(
            String subject,
            String owner,
            String cause,
            String action,
            String reverify) {
    }
}
