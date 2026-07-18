package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupPort;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class DefaultSealedEvidencePackageQueryService implements SealedEvidencePackageQueryService {

    private static final String LIGHTWEIGHT_SELECT = "select "
            + "package_id, correlation_id, tenant_id, user_id, captured_at, "
            + "request_facts_json, auth_state_json, baseline_snapshot_json, rag_results_json, "
            + "system_prompt_text, user_prompt_text, prompt_hash, system_prompt_hash, user_prompt_hash, "
            + "raw_system_prompt_hash, raw_user_prompt_hash, seal_state, seal_failure_reason, "
            + "decision_json, package_hash, schema_version, sealed, expires_at, created_at "
            + "from sealed_evidence_package";

    private final SealedEvidencePackageLookupPort lookupService;
    private final JdbcTemplate jdbcTemplate;

    public DefaultSealedEvidencePackageQueryService(
            SealedEvidencePackageLookupPort lookupService,
            JdbcTemplate jdbcTemplate) {
        this.lookupService = Objects.requireNonNull(lookupService, "lookupService");
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public Optional<SealedEvidencePackage> findByPackageId(String packageId) {
        return lookupService.findByPackageId(packageId);
    }

    @Override
    public Optional<SealedEvidencePackage> findLightweightByPackageId(String packageId) {
        if (!StringUtils.hasText(packageId)) {
            return Optional.empty();
        }
        List<SealedEvidencePackage> rows = jdbcTemplate.query(
                LIGHTWEIGHT_SELECT + " where package_id = ?",
                this::mapLightweightPackage,
                packageId.trim());
        return rows.stream().findFirst();
    }

    @Override
    public Page<SealedEvidencePackage> searchRecent(Instant from, Instant to, Pageable pageable) {
        return searchLightweight(null, null, from, to, pageable);
    }

    @Override
    public Page<SealedEvidencePackage> searchByTenantId(String tenantId, Instant from, Instant to, Pageable pageable) {
        if (!StringUtils.hasText(tenantId)) {
            return Page.empty(pageable == null ? Pageable.ofSize(20) : pageable);
        }
        return searchLightweight("tenant_id", tenantId.trim(), from, to, pageable);
    }

    @Override
    public Page<SealedEvidencePackage> searchByUserId(String userId, Instant from, Instant to, Pageable pageable) {
        if (!StringUtils.hasText(userId)) {
            return Page.empty(pageable == null ? Pageable.ofSize(20) : pageable);
        }
        return searchLightweight("user_id", userId.trim(), from, to, pageable);
    }

    @Override
    public boolean verifyIntegrity(SealedEvidencePackage evidencePackage) {
        return lookupService.verifyIntegrity(evidencePackage);
    }

    private Page<SealedEvidencePackage> searchLightweight(
            String filterColumn,
            String filterValue,
            Instant from,
            Instant to,
            Pageable pageable) {
        Instant safeFrom = from == null ? Instant.EPOCH : from;
        Instant safeTo = to == null ? Instant.now() : to;
        Pageable safePageable = pageable == null ? Pageable.ofSize(20) : pageable;
        List<Object> parameters = new ArrayList<>();
        StringBuilder where = new StringBuilder(" where captured_at >= ? and captured_at <= ?");
        parameters.add(Timestamp.from(safeFrom));
        parameters.add(Timestamp.from(safeTo));
        if (StringUtils.hasText(filterColumn) && StringUtils.hasText(filterValue)) {
            where.append(" and ").append(filterColumn).append(" = ?");
            parameters.add(filterValue);
        }
        parameters.add(safePageable.getPageSize());
        parameters.add(safePageable.getOffset());
        List<SealedEvidencePackage> rows = jdbcTemplate.query(
                LIGHTWEIGHT_SELECT + where + " order by captured_at desc limit ? offset ?",
                this::mapLightweightPackage,
                parameters.toArray());
        long observedTotal = safePageable.getOffset() + rows.size();
        if (rows.size() == safePageable.getPageSize()) {
            observedTotal++;
        }
        return new PageImpl<>(rows, safePageable, observedTotal);
    }

    private SealedEvidencePackage mapLightweightPackage(ResultSet rs, int rowNum) throws SQLException {
        SealedEvidencePackage pkg = new SealedEvidencePackage();
        Timestamp capturedAt = rs.getTimestamp("captured_at");
        Timestamp expiresAt = rs.getTimestamp("expires_at");
        Timestamp createdAt = rs.getTimestamp("created_at");
        pkg.setPackageId(rs.getString("package_id"));
        pkg.setCorrelationId(rs.getString("correlation_id"));
        pkg.setTenantId(rs.getString("tenant_id"));
        pkg.setUserId(rs.getString("user_id"));
        pkg.setCapturedAt(capturedAt == null ? null : capturedAt.toInstant());
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
        pkg.setSchemaVersion(rs.getInt("schema_version"));
        pkg.setSealed(rs.getBoolean("sealed"));
        pkg.setExpiresAt(expiresAt == null ? null : expiresAt.toInstant());
        pkg.setCreatedAt(createdAt == null ? null : createdAt.toInstant());
        return pkg;
    }
}
