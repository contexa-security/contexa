package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.jdbc.core.JdbcOperations;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public final class JdbcSealedEvidencePackageRepository implements SealedEvidencePackageRepository {

    private static final String SELECT_COLUMNS = """
            select id, package_id, correlation_id, tenant_id, user_id, captured_at,
                   request_facts_json, auth_state_json, canonical_context_json,
                   baseline_snapshot_json, rag_results_json,
                   raw_system_prompt, raw_user_prompt, system_prompt_text, user_prompt_text,
                   prompt_hash, system_prompt_hash, user_prompt_hash,
                   raw_system_prompt_hash, raw_user_prompt_hash,
                   prompt_execution_metadata_json, prompt_evidence_manifest_json,
                   seal_state, seal_failure_reason, decision_json, package_hash,
                   schema_version, sealed, expires_at, created_at
              from sealed_evidence_package
            """;
    private static final String INSERT_SQL = """
            insert into sealed_evidence_package (
                package_id, correlation_id, tenant_id, user_id, captured_at,
                request_facts_json, auth_state_json, canonical_context_json,
                baseline_snapshot_json, rag_results_json,
                raw_system_prompt, raw_user_prompt, system_prompt_text, user_prompt_text,
                prompt_hash, system_prompt_hash, user_prompt_hash,
                raw_system_prompt_hash, raw_user_prompt_hash,
                prompt_execution_metadata_json, prompt_evidence_manifest_json,
                seal_state, seal_failure_reason, decision_json, package_hash,
                schema_version, sealed, expires_at, created_at
            ) values (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            returning id
            """;
    private static final String UPDATE_SQL = """
            update sealed_evidence_package
               set package_id = ?, correlation_id = ?, tenant_id = ?, user_id = ?, captured_at = ?,
                   request_facts_json = ?, auth_state_json = ?, canonical_context_json = ?,
                   baseline_snapshot_json = ?, rag_results_json = ?,
                   raw_system_prompt = ?, raw_user_prompt = ?, system_prompt_text = ?, user_prompt_text = ?,
                   prompt_hash = ?, system_prompt_hash = ?, user_prompt_hash = ?,
                   raw_system_prompt_hash = ?, raw_user_prompt_hash = ?,
                   prompt_execution_metadata_json = ?, prompt_evidence_manifest_json = ?,
                   seal_state = ?, seal_failure_reason = ?, decision_json = ?, package_hash = ?,
                   schema_version = ?, sealed = ?, expires_at = ?
             where id = ?
            """;

    private final JdbcOperations jdbcOperations;

    public JdbcSealedEvidencePackageRepository(JdbcOperations jdbcOperations) {
        this.jdbcOperations = Objects.requireNonNull(jdbcOperations, "jdbcOperations");
    }

    @Override
    public SealedEvidencePackage save(SealedEvidencePackage evidencePackage) {
        Objects.requireNonNull(evidencePackage, "evidencePackage");
        if (evidencePackage.getId() == null) {
            return insert(evidencePackage);
        }
        if (evidencePackage.isSealed()) {
            throw new IllegalStateException("Sealed evidence package cannot be modified after persistence");
        }
        Object[] updateArguments = Arrays.copyOf(mutableArguments(evidencePackage), 29);
        updateArguments[28] = evidencePackage.getId();
        int updated = jdbcOperations.update(UPDATE_SQL, updateArguments);
        if (updated != 1) {
            throw new IllegalStateException("Sealed evidence package does not exist: " + evidencePackage.getId());
        }
        return evidencePackage;
    }

    @Override
    public Optional<SealedEvidencePackage> findByPackageId(String packageId) {
        return first(SELECT_COLUMNS + " where package_id = ?", packageId);
    }

    @Override
    public Optional<SealedEvidencePackage> findByCorrelationId(String correlationId) {
        return first(SELECT_COLUMNS + " where correlation_id = ?", correlationId);
    }

    @Override
    public Page<SealedEvidencePackage> findByUserIdAndCapturedAtBetweenOrderByCapturedAtDesc(
            String userId, Instant from, Instant to, Pageable pageable) {
        return page(" where user_id = ? and captured_at between ? and ?", pageable,
                userId, timestamp(from), timestamp(to));
    }

    @Override
    public Page<SealedEvidencePackage> findByTenantIdAndCapturedAtBetweenOrderByCapturedAtDesc(
            String tenantId, Instant from, Instant to, Pageable pageable) {
        return page(" where tenant_id = ? and captured_at between ? and ?", pageable,
                tenantId, timestamp(from), timestamp(to));
    }

    @Override
    public Page<SealedEvidencePackage> findByCapturedAtBetweenOrderByCapturedAtDesc(
            Instant from, Instant to, Pageable pageable) {
        return page(" where captured_at between ? and ?", pageable, timestamp(from), timestamp(to));
    }

    @Override
    public long countByTenantIdAndCapturedAtAfter(String tenantId, Instant after) {
        Long count = jdbcOperations.queryForObject(
                "select count(*) from sealed_evidence_package where tenant_id = ? and captured_at > ?",
                Long.class,
                tenantId,
                timestamp(after));
        return count == null ? 0L : count;
    }

    @Override
    public long deleteByExpiresAtBefore(Instant now) {
        return jdbcOperations.update(
                "delete from sealed_evidence_package where expires_at < ?",
                timestamp(now));
    }

    private SealedEvidencePackage insert(SealedEvidencePackage evidencePackage) {
        Instant createdAt = evidencePackage.getCreatedAt() == null
                ? Instant.now()
                : evidencePackage.getCreatedAt();
        Object[] mutable = mutableArguments(evidencePackage);
        Object[] insertArguments = Arrays.copyOf(mutable, 29);
        insertArguments[28] = timestamp(createdAt);
        Long id = jdbcOperations.queryForObject(INSERT_SQL, Long.class, insertArguments);
        if (id == null) {
            throw new IllegalStateException("Sealed evidence package insert did not return an identifier.");
        }
        evidencePackage.setId(id);
        evidencePackage.setCreatedAt(createdAt);
        return evidencePackage;
    }

    private Optional<SealedEvidencePackage> first(String sql, Object... arguments) {
        return jdbcOperations.query(sql, this::map, arguments).stream().findFirst();
    }

    private Page<SealedEvidencePackage> page(
            String whereClause,
            Pageable pageable,
            Object... parameters) {
        Objects.requireNonNull(pageable, "pageable");
        Object[] queryArguments = Arrays.copyOf(parameters, parameters.length + 2);
        queryArguments[parameters.length] = pageable.getPageSize();
        queryArguments[parameters.length + 1] = pageable.getOffset();
        List<SealedEvidencePackage> content = jdbcOperations.query(
                SELECT_COLUMNS + whereClause + " order by captured_at desc limit ? offset ?",
                this::map,
                queryArguments);
        Long total = jdbcOperations.queryForObject(
                "select count(*) from sealed_evidence_package" + whereClause,
                Long.class,
                parameters);
        return new PageImpl<>(content, pageable, total == null ? 0L : total);
    }

    private Object[] mutableArguments(SealedEvidencePackage evidencePackage) {
        return new Object[] {
                evidencePackage.getPackageId(), evidencePackage.getCorrelationId(),
                evidencePackage.getTenantId(), evidencePackage.getUserId(),
                timestamp(evidencePackage.getCapturedAt()), evidencePackage.getRequestFactsJson(),
                evidencePackage.getAuthStateJson(), evidencePackage.getCanonicalContextJson(),
                evidencePackage.getBaselineSnapshotJson(), evidencePackage.getRagResultsJson(),
                evidencePackage.getRawSystemPrompt(), evidencePackage.getRawUserPrompt(),
                evidencePackage.getSystemPromptText(), evidencePackage.getUserPromptText(),
                evidencePackage.getPromptHash(), evidencePackage.getSystemPromptHash(),
                evidencePackage.getUserPromptHash(), evidencePackage.getRawSystemPromptHash(),
                evidencePackage.getRawUserPromptHash(), evidencePackage.getPromptExecutionMetadataJson(),
                evidencePackage.getPromptEvidenceManifestJson(), evidencePackage.getSealState(),
                evidencePackage.getSealFailureReason(), evidencePackage.getDecisionJson(),
                evidencePackage.getPackageHash(), evidencePackage.getSchemaVersion(),
                evidencePackage.isSealed(), timestamp(evidencePackage.getExpiresAt())
        };
    }

    private SealedEvidencePackage map(ResultSet resultSet, int rowNumber) throws SQLException {
        return SealedEvidencePackage.builder()
                .id(resultSet.getLong("id"))
                .packageId(resultSet.getString("package_id"))
                .correlationId(resultSet.getString("correlation_id"))
                .tenantId(resultSet.getString("tenant_id"))
                .userId(resultSet.getString("user_id"))
                .capturedAt(instant(resultSet.getTimestamp("captured_at")))
                .requestFactsJson(resultSet.getString("request_facts_json"))
                .authStateJson(resultSet.getString("auth_state_json"))
                .canonicalContextJson(resultSet.getString("canonical_context_json"))
                .baselineSnapshotJson(resultSet.getString("baseline_snapshot_json"))
                .ragResultsJson(resultSet.getString("rag_results_json"))
                .rawSystemPrompt(resultSet.getString("raw_system_prompt"))
                .rawUserPrompt(resultSet.getString("raw_user_prompt"))
                .systemPromptText(resultSet.getString("system_prompt_text"))
                .userPromptText(resultSet.getString("user_prompt_text"))
                .promptHash(resultSet.getString("prompt_hash"))
                .systemPromptHash(resultSet.getString("system_prompt_hash"))
                .userPromptHash(resultSet.getString("user_prompt_hash"))
                .rawSystemPromptHash(resultSet.getString("raw_system_prompt_hash"))
                .rawUserPromptHash(resultSet.getString("raw_user_prompt_hash"))
                .promptExecutionMetadataJson(resultSet.getString("prompt_execution_metadata_json"))
                .promptEvidenceManifestJson(resultSet.getString("prompt_evidence_manifest_json"))
                .sealState(resultSet.getString("seal_state"))
                .sealFailureReason(resultSet.getString("seal_failure_reason"))
                .decisionJson(resultSet.getString("decision_json"))
                .packageHash(resultSet.getString("package_hash"))
                .schemaVersion(resultSet.getInt("schema_version"))
                .sealed(resultSet.getBoolean("sealed"))
                .expiresAt(instant(resultSet.getTimestamp("expires_at")))
                .createdAt(instant(resultSet.getTimestamp("created_at")))
                .build();
    }

    private Timestamp timestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    private Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}