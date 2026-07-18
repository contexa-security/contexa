package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

public final class OfficialRunLightweightEvidenceReader {

    private static final Logger log = LoggerFactory.getLogger(OfficialRunLightweightEvidenceReader.class);
    private static final int PROMPT_PREVIEW_LIMIT = 900;
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() { };
    private static final String LIGHTWEIGHT_EVIDENCE_SQL = """
            SELECT package_id,
                   correlation_id,
                   tenant_id,
                   user_id,
                   captured_at,
                   request_facts_json,
                   auth_state_json,
                   baseline_snapshot_json,
                   rag_results_json,
                   system_prompt_text,
                   user_prompt_text,
                   prompt_hash,
                   system_prompt_hash,
                   user_prompt_hash,
                   raw_system_prompt_hash,
                   raw_user_prompt_hash,
                   seal_state,
                   seal_failure_reason,
                   decision_json,
                   package_hash,
                   schema_version,
                   sealed,
                   expires_at,
                   created_at
              FROM sealed_evidence_package
             WHERE package_id = ?
            """;
    private final JdbcOperations jdbcOperations;
    private final ObjectMapper objectMapper;
    private final RuntimeEvidencePromptConsistencyGate promptConsistencyGate;
    private final PromptQualityRuntimeEvidenceService evidenceService;
    private final PromptQualityMessageResolver messageResolver;

    public OfficialRunLightweightEvidenceReader(
            JdbcOperations jdbcOperations,
            ObjectMapper objectMapper,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            PromptQualityRuntimeEvidenceService evidenceService,
            PromptQualityMessageResolver messageResolver) {
        this.jdbcOperations = Objects.requireNonNull(jdbcOperations, "jdbcOperations");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.promptConsistencyGate = Objects.requireNonNull(promptConsistencyGate, "promptConsistencyGate");
        this.evidenceService = Objects.requireNonNull(evidenceService, "evidenceService");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    RuntimeEvidencePackageDetail findDetail(String packageId) {
        try {
            SealedEvidencePackage pkg = jdbcOperations.queryForObject(
                    LIGHTWEIGHT_EVIDENCE_SQL,
                    this::mapLightweightEvidence,
                    packageId);
            return pkg == null ? evidenceService.findDetail(packageId) : toDetail(pkg);
        }
        catch (DataAccessException exception) {
            log.error("[PQA-OFFICIAL-DETAIL] Lightweight evidence lookup failed; falling back to full evidence detail. packageId={}",
                    packageId,
                    exception);
            return evidenceService.findDetail(packageId);
        }
    }

    private SealedEvidencePackage mapLightweightEvidence(ResultSet rs, int rowNum) throws SQLException {
        SealedEvidencePackage pkg = new SealedEvidencePackage();
        pkg.setPackageId(rs.getString("package_id"));
        pkg.setCorrelationId(rs.getString("correlation_id"));
        pkg.setTenantId(rs.getString("tenant_id"));
        pkg.setUserId(rs.getString("user_id"));
        pkg.setCapturedAt(instant(rs, "captured_at"));
        pkg.setRequestFactsJson(rs.getString("request_facts_json"));
        pkg.setAuthStateJson(rs.getString("auth_state_json"));
        pkg.setBaselineSnapshotJson(rs.getString("baseline_snapshot_json"));
        pkg.setRagResultsJson(rs.getString("rag_results_json"));
        pkg.setSystemPromptText(rs.getString("system_prompt_text"));
        pkg.setUserPromptText(rs.getString("user_prompt_text"));
        pkg.setPromptHash(rs.getString("prompt_hash"));
        pkg.setSystemPromptHash(rs.getString("system_prompt_hash"));
        pkg.setUserPromptHash(rs.getString("user_prompt_hash"));
        pkg.setRawSystemPromptHash(rs.getString("raw_system_prompt_hash"));
        pkg.setRawUserPromptHash(rs.getString("raw_user_prompt_hash"));
        pkg.setSealState(rs.getString("seal_state"));
        pkg.setSealFailureReason(rs.getString("seal_failure_reason"));
        pkg.setDecisionJson(rs.getString("decision_json"));
        pkg.setPackageHash(rs.getString("package_hash"));
        int schemaVersion = rs.getInt("schema_version");
        pkg.setSchemaVersion(rs.wasNull() ? 2 : schemaVersion);
        pkg.setSealed(rs.getBoolean("sealed"));
        pkg.setExpiresAt(instant(rs, "expires_at"));
        pkg.setCreatedAt(instant(rs, "created_at"));
        return pkg;
    }

    private RuntimeEvidencePackageDetail toDetail(SealedEvidencePackage pkg) {
        Map<String, Object> requestFacts = parseJson(pkg.getRequestFactsJson());
        Map<String, Object> authState = parseJson(pkg.getAuthStateJson());
        Map<String, Object> promptMetadata = Map.of();
        Map<String, Object> decision = parseJson(pkg.getDecisionJson());
        Map<String, Object> baselineSnapshot = parseJson(pkg.getBaselineSnapshotJson());
        Map<String, Object> ragResults = parseJson(pkg.getRagResultsJson());
        boolean integrityValid = storedSealLooksValid(pkg);
        RuntimeEvidencePromptConsistencyResult promptConsistency = promptConsistencyGate.evaluate(pkg);
        return new RuntimeEvidencePackageDetail(
                toSummary(pkg, requestFacts, promptMetadata, decision, integrityValid),
                false,
                false,
                StringUtils.hasText(pkg.getSystemPromptText()),
                StringUtils.hasText(pkg.getUserPromptText()),
                StringUtils.hasText(pkg.getBaselineSnapshotJson()),
                StringUtils.hasText(pkg.getRagResultsJson()),
                promptPreview(pkg.getSystemPromptText()),
                promptPreview(pkg.getUserPromptText()),
                requestFacts,
                authState,
                promptMetadata,
                decision,
                baselineSnapshot,
                ragResults,
                List.of(),
                List.of(),
                qualityWarnings(pkg, integrityValid),
                promptConsistency,
                pkg.getSystemPromptText(),
                pkg.getUserPromptText());
    }

    private RuntimeEvidencePackageSummary toSummary(
            SealedEvidencePackage pkg,
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            Map<String, Object> decision,
            boolean integrityValid) {
        String requestPath = firstNonBlank(
                raw(requestFacts, "requestPath"), raw(requestFacts, "resourceUrl"),
                raw(requestFacts, "path"), raw(requestFacts, "uri"));
        String resourceId = firstNonBlank(
                raw(requestFacts, "protectableResourceId"), raw(promptMetadata, "protectableResourceId"),
                raw(requestFacts, "resourceId"), raw(requestFacts, "endpointKey"),
                raw(promptMetadata, "resourceId"), raw(promptMetadata, "endpointKey"), pkg.getPackageId());
        String httpMethod = firstNonBlank(raw(requestFacts, "httpMethod"), raw(requestFacts, "method"), "GET")
                .toUpperCase(Locale.ROOT);
        String stateLabel = integrityValid
                ? message("enterprise.pqa.runtimeEvidence.state.ready.label")
                : message("enterprise.pqa.runtimeEvidence.state.integrityWarning.label");
        String nextAction = integrityValid
                ? message("enterprise.pqa.runtimeEvidence.state.ready.nextAction")
                : message("enterprise.pqa.runtimeEvidence.state.integrityWarning.nextAction");
        return new RuntimeEvidencePackageSummary(
                pkg.getPackageId(), pkg.getCorrelationId(), pkg.getTenantId(), pkg.getUserId(), pkg.getCapturedAt(),
                requestPath, resourceId, httpMethod,
                firstNonBlank(raw(decision, "action"), raw(decision, "decisionAction")),
                doubleValue(decision, "confidence", "decisionConfidence"),
                pkg.isSealed(), integrityValid, pkg.getPromptHash(), promptTextLength(pkg), stateLabel, nextAction,
                integrityValid ? "READY" : "INTEGRITY_WARNING", null);
    }

    private List<String> qualityWarnings(SealedEvidencePackage pkg, boolean integrityValid) {
        return Stream.of(
                        StringUtils.hasText(pkg.getSystemPromptText()) ? null : message("enterprise.pqa.runtimeEvidence.warning.llmSystemPromptMissing"),
                        StringUtils.hasText(pkg.getUserPromptText()) ? null : message("enterprise.pqa.runtimeEvidence.warning.llmUserPromptMissing"),
                        integrityValid ? null : message("enterprise.pqa.runtimeEvidence.warning.integrityMismatch"))
                .filter(StringUtils::hasText)
                .toList();
    }

    private Map<String, Object> parseJson(String json) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            Map<String, Object> parsed = objectMapper.readValue(json, MAP_TYPE);
            return parsed == null ? Map.of() : parsed;
        }
        catch (Exception ignored) {
            return Map.of();
        }
    }

    private Double doubleValue(Map<String, Object> map, String... keys) {
        if (map == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            Object value = map.get(key);
            if (value instanceof Number number) {
                return number.doubleValue();
            }
            if (value != null) {
                try {
                    return Double.parseDouble(String.valueOf(value));
                }
                catch (NumberFormatException ignored) {
                    // Try next key.
                }
            }
        }
        return null;
    }

    private int promptTextLength(SealedEvidencePackage pkg) {
        int systemLength = pkg.getSystemPromptText() == null ? 0 : pkg.getSystemPromptText().length();
        int userLength = pkg.getUserPromptText() == null ? 0 : pkg.getUserPromptText().length();
        return systemLength + userLength;
    }

    private String promptPreview(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String normalized = value.trim();
        return normalized.length() <= PROMPT_PREVIEW_LIMIT
                ? normalized
                : normalized.substring(0, PROMPT_PREVIEW_LIMIT) + "\n...";
    }

    private boolean storedSealLooksValid(SealedEvidencePackage pkg) {
        return pkg.isSealed()
                && StringUtils.hasText(pkg.getPackageHash())
                && !"FAILED".equalsIgnoreCase(firstNonBlank(pkg.getSealState(), "SEALED"));
    }

    private Instant instant(ResultSet rs, String column) throws SQLException {
        Timestamp timestamp = rs.getTimestamp(column);
        return timestamp == null ? null : timestamp.toInstant();
    }

    private String raw(Map<String, Object> raw, String key) {
        return raw == null || raw.get(key) == null ? null : String.valueOf(raw.get(key));
    }

    private String firstNonBlank(String... values) {
        if (values != null) {
            for (String value : values) {
                if (StringUtils.hasText(value)) {
                    return value.trim();
                }
            }
        }
        return "";
    }

    private String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }
}