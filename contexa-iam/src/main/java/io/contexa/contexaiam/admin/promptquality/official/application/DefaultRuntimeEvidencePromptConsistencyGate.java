package io.contexa.contexaiam.admin.promptquality.official.application;

import static io.contexa.contexaiam.admin.promptquality.official.application.RuntimeEvidencePromptValueMatcher.containsValue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;
import io.contexa.contexaiam.admin.promptquality.official.application.support.AbstractPromptQualityRuntimeEvidenceSupport;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class DefaultRuntimeEvidencePromptConsistencyGate
        extends AbstractPromptQualityRuntimeEvidenceSupport
        implements RuntimeEvidencePromptConsistencyGate {

    public static final String ISSUE_METRIC_CODE = "EVIDENCE_PROMPT_MISMATCH";
    private static final String SOURCE_PROMPT_HASH = "promptHash";
    private static final String SOURCE_PROMPT_CAPTURE = "promptCapture";
    private static final String SOURCE_REQUEST_FACT = "requestFacts";
    private static final String SOURCE_SEALED_PACKAGE = "sealedEvidencePackage";
    private static final String SOURCE_PROMPT_METADATA = "promptExecutionMetadata";

    public DefaultRuntimeEvidencePromptConsistencyGate(
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver) {
        super(objectMapper, messageResolver);
    }

    @Override
    public RuntimeEvidencePromptConsistencyResult evaluate(SealedEvidencePackage evidencePackage) {
        if (evidencePackage == null) {
            return RuntimeEvidencePromptConsistencyResult.empty();
        }
        Map<String, Object> requestFacts = parseJson(evidencePackage.getRequestFactsJson());
        Map<String, Object> promptMetadata = parsePromptExecutionMetadataHeader(evidencePackage.getPromptExecutionMetadataJson());
        List<RuntimeEvidenceCheckResult> checks = new ArrayList<>();
        List<String> findings = new ArrayList<>();
        List<String> nextActions = new ArrayList<>();
        GateState state = new GateState();

        String systemPrompt = safe(evidencePackage.getSystemPromptText());
        String userPrompt = safe(evidencePackage.getUserPromptText());
        String rawSystemPrompt = safe(evidencePackage.getRawSystemPrompt());
        String rawUserPrompt = safe(evidencePackage.getRawUserPrompt());

        addBlocking(checks, findings, nextActions, state,
                "LLM system/user prompt captured",
                "system and user prompts",
                captured(systemPrompt, userPrompt),
                hasText(systemPrompt) && hasText(userPrompt),
                SOURCE_PROMPT_CAPTURE);
        addBlocking(checks, findings, nextActions, state,
                "promptHash recalculates from LLM prompt",
                firstNonBlank(evidencePackage.getPromptHash(), text(promptMetadata, "promptHash"), "declared promptHash"),
                promptHashActual(evidencePackage, promptMetadata, systemPrompt, userPrompt),
                promptHashMatches(evidencePackage, promptMetadata, systemPrompt, userPrompt),
                SOURCE_PROMPT_HASH);
        addBlocking(checks, findings, nextActions, state,
                "systemPromptHash matches LLM system prompt",
                firstNonBlank(text(promptMetadata, "systemPromptHash"), "metadata systemPromptHash"),
                sha256(systemPrompt),
                hashMatches(text(promptMetadata, "systemPromptHash"), systemPrompt),
                SOURCE_PROMPT_HASH);
        addBlocking(checks, findings, nextActions, state,
                "userPromptHash matches LLM user prompt",
                firstNonBlank(text(promptMetadata, "userPromptHash"), "metadata userPromptHash"),
                sha256(userPrompt),
                hashMatches(text(promptMetadata, "userPromptHash"), userPrompt),
                SOURCE_PROMPT_HASH);
        addBlocking(checks, findings, nextActions, state,
                "raw prompt and LLM prompt difference is recorded",
                "same prompt or compression metadata",
                rawPromptDiffLabel(rawSystemPrompt, rawUserPrompt, systemPrompt, userPrompt, promptMetadata),
                rawPromptParityRecorded(rawSystemPrompt, rawUserPrompt, systemPrompt, userPrompt, promptMetadata),
                SOURCE_PROMPT_CAPTURE);

        addTracePresenceCheck(checks, findings, nextActions, state,
                "requestId",
                firstAvailable("requestId",
                        fact(requestFacts, SOURCE_REQUEST_FACT, "requestId"),
                        fact(promptMetadata, SOURCE_PROMPT_METADATA, "requestId"),
                        factValue("requestId", evidencePackage.getCorrelationId(), SOURCE_SEALED_PACKAGE + ".correlationId")));
        addTracePresenceCheck(checks, findings, nextActions, state,
                "correlationId",
                firstAvailable("correlationId",
                        fact(requestFacts, SOURCE_REQUEST_FACT, "correlationId"),
                        fact(promptMetadata, SOURCE_PROMPT_METADATA, "correlationId"),
                        factValue("correlationId", evidencePackage.getCorrelationId(), SOURCE_SEALED_PACKAGE + ".correlationId")));
        addBlockingFactChecks(checks, findings, nextActions, state, requestFacts, SOURCE_REQUEST_FACT, userPrompt, "requestPath", "resourceUrl", "path", "uri");
        addBlockingFactChecks(checks, findings, nextActions, state, requestFacts, SOURCE_REQUEST_FACT, userPrompt, "resourceId", "endpointKey");
        addBlockingFactChecks(checks, findings, nextActions, state, requestFacts, SOURCE_REQUEST_FACT, userPrompt, "httpMethod", "method");

        String gateState = state.blocked ? "BLOCKED" : "PASS";
        return new RuntimeEvidencePromptConsistencyResult(
                gateState,
                stateLabel(gateState),
                "PASS".equals(gateState),
                state.blocked,
                List.copyOf(checks),
                findings.stream().distinct().toList(),
                nextActions.stream().filter(StringUtils::hasText).distinct().toList());
    }

    private void addBlockingFactChecks(
            List<RuntimeEvidenceCheckResult> checks,
            List<String> findings,
            List<String> nextActions,
            GateState state,
            Map<String, Object> facts,
            String source,
            String userPrompt,
            String... keys) {
        addBlockingFactCheck(checks, findings, nextActions, state, fact(facts, source, keys), userPrompt);
    }

    private void addBlockingFactCheck(
            List<RuntimeEvidenceCheckResult> checks,
            List<String> findings,
            List<String> nextActions,
            GateState state,
            EvidenceFact fact,
            String userPrompt) {
        String key = fact == null || !StringUtils.hasText(fact.key()) ? "fact" : fact.key();
        String value = fact == null ? null : fact.value();
        String source = fact == null || !StringUtils.hasText(fact.source()) ? SOURCE_REQUEST_FACT : fact.source();
        if (!StringUtils.hasText(value)) {
            addBlocking(checks, findings, nextActions, state,
                    key + " exists in sealed evidence",
                    key + " value",
                    "missing",
                    false,
                    source);
            return;
        }
        addBlocking(checks, findings, nextActions, state,
                key + " is reflected in user prompt",
                value,
                containsValue(userPrompt, value) ? "present" : "missing",
                containsValue(userPrompt, value),
                source);
    }

    private void addTracePresenceCheck(
            List<RuntimeEvidenceCheckResult> checks,
            List<String> findings,
            List<String> nextActions,
            GateState state,
            String key,
            EvidenceFact fact) {
        String value = fact == null ? null : fact.value();
        String source = fact == null || !StringUtils.hasText(fact.source()) ? SOURCE_SEALED_PACKAGE : fact.source();
        if (!StringUtils.hasText(value)) {
            addBlocking(checks, findings, nextActions, state,
                    key + " is traceable in sealed evidence",
                    key + " value",
                    "missing",
                    false,
                    source);
            return;
        }
        addBlocking(checks, findings, nextActions, state,
                key + " is traceable in sealed evidence",
                key + " value",
                value,
                true,
                source);
    }

    private void addBlocking(
            List<RuntimeEvidenceCheckResult> checks,
            List<String> findings,
            List<String> nextActions,
            GateState state,
            String label,
            String expected,
            String actual,
            boolean pass,
            String source) {
        add(checks, findings, nextActions, label, expected, actual, pass, source);
        if (!pass) {
            state.blocked = true;
        }
    }

    private void add(
            List<RuntimeEvidenceCheckResult> checks,
            List<String> findings,
            List<String> nextActions,
            String label,
            String expected,
            String actual,
            boolean pass,
            String source) {
        checks.add(new RuntimeEvidenceCheckResult(ISSUE_METRIC_CODE, label, expected, actual, pass, source));
        if (!pass) {
            findings.add(message("enterprise.pqa.consistency.gate.dynamic.issue",
                    gateLabel(label), operatorValue(actual), gateTarget(label, source)));
            nextActions.add(message("enterprise.pqa.consistency.gate.dynamic.hint"));
        }
    }

    private String gateLabel(String label) {
        String normalized = label == null ? "" : label.trim().toLowerCase(Locale.ROOT);
        if (normalized.contains("prompt hash")) return message("enterprise.pqa.consistency.gate.dynamic.label.promptHash");
        if (normalized.contains("system prompt")) return message("enterprise.pqa.consistency.gate.dynamic.label.systemPrompt");
        if (normalized.contains("user prompt")) return message("enterprise.pqa.consistency.gate.dynamic.label.userPrompt");
        if (normalized.contains("resource")) return message("enterprise.pqa.consistency.gate.dynamic.label.resource");
        if (normalized.contains("request")) return message("enterprise.pqa.consistency.gate.dynamic.label.request");
        if (normalized.contains("tenant")) return message("enterprise.pqa.consistency.gate.dynamic.label.tenant");
        if (normalized.contains("user")) return message("enterprise.pqa.consistency.gate.dynamic.label.user");
        if (normalized.contains("governance")) return message("enterprise.pqa.consistency.gate.dynamic.label.governance");
        return message("enterprise.pqa.consistency.gate.dynamic.label.default");
    }

    private String gateTarget(String label, String source) {
        String normalized = label == null ? "" : label.trim().toLowerCase(Locale.ROOT);
        if (normalized.contains("clientip")) return "clientIp";
        if (normalized.contains("raw prompt") || normalized.contains("llm prompt difference")) {
            return "rawPrompt/finalLlmPrompt";
        }
        if (normalized.contains("governance")) return "promptGovernance.governanceDescriptor";
        if (StringUtils.hasText(source)) return source.trim();
        return message("enterprise.pqa.consistency.gate.dynamic.target.evidencePrompt");
    }

    private String operatorValue(String value) {
        if (!StringUtils.hasText(value)) {
            return message("enterprise.pqa.consistency.gate.notEvaluated");
        }
        return switch (value.trim().toLowerCase(Locale.ROOT)) {
            case "present", "matched", "pass" -> message("enterprise.pqa.consistency.gate.state.present");
            case "missing" -> message("enterprise.pqa.consistency.gate.state.missing");
            case "mismatched" -> message("enterprise.pqa.consistency.gate.hashMismatch");
            default -> value.trim();
        };
    }

    private boolean promptHashMatches(
            SealedEvidencePackage evidencePackage,
            Map<String, Object> promptMetadata,
            String systemPrompt,
            String userPrompt) {
        String declared = firstNonBlank(evidencePackage.getPromptHash(), text(promptMetadata, "promptHash"));
        return StringUtils.hasText(declared) && declared.equals(sha256(systemPrompt + "\n---\n" + userPrompt));
    }

    private String promptHashActual(
            SealedEvidencePackage evidencePackage,
            Map<String, Object> promptMetadata,
            String systemPrompt,
            String userPrompt) {
        return "declared=" + firstNonBlank(evidencePackage.getPromptHash(), text(promptMetadata, "promptHash"), "missing")
                + ", recalculated=" + sha256(systemPrompt + "\n---\n" + userPrompt);
    }

    private boolean hashMatches(String declaredHash, String promptText) {
        return StringUtils.hasText(declaredHash) && declaredHash.equals(sha256(safe(promptText)));
    }

    private boolean rawPromptParityRecorded(
            String rawSystemPrompt,
            String rawUserPrompt,
            String systemPrompt,
            String userPrompt,
            Map<String, Object> promptMetadata) {
        if (!hasText(rawSystemPrompt) || !hasText(rawUserPrompt) || !hasText(systemPrompt) || !hasText(userPrompt)) {
            return false;
        }
        boolean same = promptParityEquals(rawSystemPrompt, systemPrompt)
                && promptParityEquals(rawUserPrompt, userPrompt);
        return same || bool(promptMetadata, "promptCompressionApplied") || layoutOnlyNormalizationRecorded(promptMetadata);
    }

    private String rawPromptDiffLabel(
            String rawSystemPrompt,
            String rawUserPrompt,
            String systemPrompt,
            String userPrompt,
            Map<String, Object> promptMetadata) {
        if (!hasText(rawSystemPrompt) || !hasText(rawUserPrompt)) {
            return "raw prompt missing";
        }
        if (!hasText(systemPrompt) || !hasText(userPrompt)) {
            return "LLM prompt missing";
        }
        boolean same = promptParityEquals(rawSystemPrompt, systemPrompt)
                && promptParityEquals(rawUserPrompt, userPrompt);
        if (same) {
            return "same";
        }
        if (layoutOnlyNormalizationRecorded(promptMetadata)) {
            return "layout-only normalization";
        }
        return "different, compressionApplied=" + bool(promptMetadata, "promptCompressionApplied");
    }

    private boolean layoutOnlyNormalizationRecorded(Map<String, Object> promptMetadata) {
        Object ledger = promptMetadata == null ? null : promptMetadata.get("promptCompressionLedger");
        if (!(ledger instanceof List<?> records) || records.isEmpty()) {
            return false;
        }
        for (Object record : records) {
            if (!(record instanceof Map<?, ?> map)) {
                return false;
            }
            String action = String.valueOf(map.get("action"));
            String scopeKey = String.valueOf(map.get("scopeKey"));
            String reason = String.valueOf(map.get("reason"));
            boolean layoutScope = "SYSTEM_PROMPT_LAYOUT".equals(scopeKey) || "USER_PROMPT_LAYOUT".equals(scopeKey);
            boolean whitespaceOnly = reason.toLowerCase(Locale.ROOT).contains("whitespace-only normalization");
            if (!"TRIMMED".equals(action) || !layoutScope || !whitespaceOnly) {
                return false;
            }
        }
        return true;
    }

    private boolean promptParityEquals(String left, String right) {
        if (left == null || right == null) {
            return false;
        }
        return normalizePromptForParity(left).equals(normalizePromptForParity(right));
    }

    private String normalizePromptForParity(String value) {
        return value == null ? "" : value.replace("\r\n", "\n").replace('\r', '\n').stripTrailing();
    }

    private EvidenceFact fact(Map<String, Object> facts, String source, String... keys) {
        if (keys == null) {
            return new EvidenceFact("fact", null, source);
        }
        String primaryKey = keys.length == 0 ? "fact" : keys[0];
        for (String key : keys) {
            String value = text(facts, key);
            if (StringUtils.hasText(value)) {
                return new EvidenceFact(primaryKey, value, source + "." + key);
            }
        }
        return new EvidenceFact(primaryKey, null, source);
    }

    private EvidenceFact factValue(String key, String value, String source) {
        return new EvidenceFact(key, value, source);
    }

    private EvidenceFact firstAvailable(String key, EvidenceFact... facts) {
        if (facts == null) {
            return new EvidenceFact(key, null, SOURCE_SEALED_PACKAGE);
        }
        for (EvidenceFact fact : facts) {
            if (fact != null && StringUtils.hasText(fact.value())) {
                return new EvidenceFact(key, fact.value(), fact.source());
            }
        }
        String source = facts.length > 0 && facts[0] != null && StringUtils.hasText(facts[0].source())
                ? facts[0].source()
                : SOURCE_SEALED_PACKAGE;
        return new EvidenceFact(key, null, source);
    }

    private String captured(String systemPrompt, String userPrompt) {
        return "system=" + (hasText(systemPrompt) ? "captured" : "missing")
                + ", user=" + (hasText(userPrompt) ? "captured" : "missing");
    }

    private boolean bool(Map<String, Object> map, String key) {
        Object value = map == null ? null : map.get(key);
        if (value instanceof Boolean bool) {
            return bool;
        }
        return value != null && Boolean.parseBoolean(String.valueOf(value));
    }

    private String sha256(String value) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(safe(value).getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(hash);
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 digest is not available.", exception);
        }
    }

    private String stateLabel(String state) {
        return switch (state) {
            case "PASS" -> message("enterprise.pqa.promptConsistency.state.pass");
            case "BLOCKED" -> message("enterprise.pqa.promptConsistency.state.blocked");
            default -> message("enterprise.pqa.promptConsistency.state.reviewRequired");
        };
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    private static class GateState {
        private boolean blocked;
    }

    private record EvidenceFact(String key, String value, String source) {
    }
}
