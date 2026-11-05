package io.contexa.contexaiam.admin.promptquality.evidence;

import io.contexa.contexacore.verification.evidence.SealedEvidenceChain;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
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

public final class JdbcSealedEvidencePackageRepository implements SealedEvidencePackageRepository, SealedEvidenceChain {

    private static final String SELECT_COLUMNS = """
            select id, package_id, correlation_id, idempotency_key, tenant_id, user_id, captured_at,
                   request_facts_json, auth_state_json, canonical_context_json,
                   baseline_snapshot_json, rag_results_json,
                   raw_system_prompt, raw_user_prompt, system_prompt_text, user_prompt_text,
                   prompt_hash, system_prompt_hash, user_prompt_hash,
                   raw_system_prompt_hash, raw_user_prompt_hash,
                   prompt_execution_metadata_json, prompt_evidence_manifest_json,
                   seal_state, seal_failure_reason, decision_json, package_hash,
                   schema_version, sealed, expires_at, created_at,
                   previous_package_hash, package_signature, signature_key_id
              from ctxa_sealed_evidence_package
            """;
    private static final String INSERT_SQL = """
            insert into ctxa_sealed_evidence_package (
                package_id, correlation_id, idempotency_key, tenant_id, user_id, captured_at,
                request_facts_json, auth_state_json, canonical_context_json,
                baseline_snapshot_json, rag_results_json,
                raw_system_prompt, raw_user_prompt, system_prompt_text, user_prompt_text,
                prompt_hash, system_prompt_hash, user_prompt_hash,
                raw_system_prompt_hash, raw_user_prompt_hash,
                prompt_execution_metadata_json, prompt_evidence_manifest_json,
                seal_state, seal_failure_reason, decision_json, package_hash,
                schema_version, sealed, expires_at, previous_package_hash, package_signature, signature_key_id,
                created_at
            ) values (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?
            )
            returning id
            """;
    /** docs/agent A5-6: the latest linked package, the one a new package is sealed after. */
    private static final String LATEST_LINKED_HASH_SQL = """
            select package_hash from ctxa_sealed_evidence_package
             where schema_version >= ? order by id desc limit 1
            """;
    /** Q-21: the capture time of the oldest signed package kept, from the capture time index. */
    private static final String OLDEST_SIGNED_SQL = """
            select captured_at from ctxa_sealed_evidence_package
             where package_signature is not null order by captured_at limit 1
            """;
    /** Q-21: walks back from the package by its key, so the package right before it answers at once. */
    private static final String PREVIOUS_KEPT_SQL = """
            select 1 from ctxa_sealed_evidence_package
             where id < ? and package_hash = ? order by id desc limit 1
            """;
    /** Q-21: the later capture time of the package kept right before this one and of the signed one kept before it. */
    private static final String CAPTURED_BEFORE_SQL = """
            select max(captured_at) from (
                (select captured_at from ctxa_sealed_evidence_package where id < ? order by id desc limit 1)
                union all
                (select captured_at from ctxa_sealed_evidence_package
                  where id < ? and package_signature is not null order by id desc limit 1)
            ) kept
            """;
    private final JdbcOperations jdbcOperations;
    /** Seals linked packages in the order this store inserts them. */
    private final Object sealLock = new Object();
    private SealedEvidencePackageIntegrity integrity;

    public JdbcSealedEvidencePackageRepository(JdbcOperations jdbcOperations) {
        this.jdbcOperations = Objects.requireNonNull(jdbcOperations, "jdbcOperations");
    }

    /**
     * docs/agent A5-6: the integrity a schema 3 package is sealed with on insert, after the package inserted before
     * it; without one a package keeps the hash it was assembled with.
     */
    public void setIntegrity(SealedEvidencePackageIntegrity integrity) {
        this.integrity = integrity;
    }

    @Override
    public Optional<Instant> signedSince() {
        return jdbcOperations.queryForList(OLDEST_SIGNED_SQL, Timestamp.class).stream().findFirst()
                .map(Timestamp::toInstant);
    }

    @Override
    public boolean previousKept(SealedEvidencePackage pkg) {
        return !jdbcOperations.queryForList(PREVIOUS_KEPT_SQL, Integer.class, pkg.getId(),
                pkg.getPreviousPackageHash()).isEmpty();
    }

    @Override
    public Optional<Instant> capturedBefore(SealedEvidencePackage pkg) {
        return Optional.ofNullable(jdbcOperations.queryForObject(CAPTURED_BEFORE_SQL, Timestamp.class, pkg.getId(),
                pkg.getId())).map(Timestamp::toInstant);
    }

    @Override
    public SealedEvidencePackage save(SealedEvidencePackage evidencePackage) {
        Objects.requireNonNull(evidencePackage, "evidencePackage");
        // A package is sealed once and only inserted; one that already has a row is never written again.
        if (evidencePackage.getId() != null) {
            throw new IllegalStateException("Sealed evidence package cannot be modified after persistence");
        }
        return insert(evidencePackage);
    }

    @Override
    public Optional<SealedEvidencePackage> findByPackageId(String packageId) {
        return first(SELECT_COLUMNS + " where package_id = ?", packageId);
    }

    @Override
    public Optional<SealedEvidencePackage> findByCorrelationId(String correlationId) {
        return first(SELECT_COLUMNS + " where correlation_id = ? order by captured_at desc limit 1", correlationId);
    }

    @Override
    public Optional<SealedEvidencePackage> findByIdempotencyKey(String idempotencyKey) {
        return first(SELECT_COLUMNS + " where idempotency_key = ?", idempotencyKey);
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
                "select count(*) from ctxa_sealed_evidence_package where tenant_id = ? and captured_at > ?",
                Long.class,
                tenantId,
                timestamp(after));
        return count == null ? 0L : count;
    }

    @Override
    public long deleteByExpiresAtBefore(Instant now) {
        return jdbcOperations.update(
                "delete from ctxa_sealed_evidence_package where expires_at < ?",
                timestamp(now));
    }

    private SealedEvidencePackage insert(SealedEvidencePackage evidencePackage) {
        if (integrity == null
                || evidencePackage.getSchemaVersion() < SealedEvidencePackageIntegrity.LINKED_SCHEMA_VERSION) {
            return insertSealed(evidencePackage);
        }
        synchronized (sealLock) {
            List<String> latest = jdbcOperations.queryForList(LATEST_LINKED_HASH_SQL, String.class,
                    SealedEvidencePackageIntegrity.LINKED_SCHEMA_VERSION);
            integrity.seal(evidencePackage, latest.isEmpty() ? null : latest.get(0));
            return insertSealed(evidencePackage);
        }
    }

    private SealedEvidencePackage insertSealed(SealedEvidencePackage evidencePackage) {
        Instant createdAt = evidencePackage.getCreatedAt() == null
                ? Instant.now()
                : evidencePackage.getCreatedAt();
        Object[] mutable = mutableArguments(evidencePackage);
        Object[] insertArguments = Arrays.copyOf(mutable, 33);
        insertArguments[29] = evidencePackage.getPreviousPackageHash();
        insertArguments[30] = evidencePackage.getPackageSignature();
        insertArguments[31] = evidencePackage.getSignatureKeyId();
        insertArguments[32] = timestamp(createdAt);
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
                "select count(*) from ctxa_sealed_evidence_package" + whereClause,
                Long.class,
                parameters);
        return new PageImpl<>(content, pageable, total == null ? 0L : total);
    }

    private Object[] mutableArguments(SealedEvidencePackage evidencePackage) {
        return new Object[] {
                evidencePackage.getPackageId(), evidencePackage.getCorrelationId(),
                evidencePackage.getIdempotencyKey(), evidencePackage.getTenantId(), evidencePackage.getUserId(),
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
                .idempotencyKey(resultSet.getString("idempotency_key"))
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
                .previousPackageHash(resultSet.getString("previous_package_hash"))
                .packageSignature(resultSet.getString("package_signature"))
                .signatureKeyId(resultSet.getString("signature_key_id"))
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