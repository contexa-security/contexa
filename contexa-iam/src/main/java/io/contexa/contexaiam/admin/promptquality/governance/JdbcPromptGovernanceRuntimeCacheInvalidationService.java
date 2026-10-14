package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexaiam.admin.promptquality.common.PromptQualityJdbcTimestamps;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

public class JdbcPromptGovernanceRuntimeCacheInvalidationService
        implements PromptGovernanceRuntimeCacheInvalidationService {

    private static final String DEFAULT_SCOPE = "PLATFORM_GLOBAL";

    private final JdbcTemplate jdbcTemplate;

    public JdbcPromptGovernanceRuntimeCacheInvalidationService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public PromptGovernanceCacheInvalidation publish(
            String registryScope,
            String promptKey,
            String promptVersion,
            String reason,
            String publishedBy) {
        String eventId = "pqa-cache-" + UUID.randomUUID();
        Timestamp now = PromptQualityJdbcTimestamps.toTimestamp(PromptQualityJdbcTimestamps.nowText());
        String scope = safeScope(registryScope);
        String key = require(promptKey, "promptKey");
        String version = require(promptVersion, "promptVersion");
        // PV-23: the event names the release's template key and contract version, read from the registry; a version
        // without a registry row names none, which clears every template key of the prompt key.
        List<Map<String, Object>> release = jdbcTemplate.queryForList(
                """
                        select template_key, contract_version
                          from prompt_governance_registry
                         where registry_scope = ?
                           and prompt_key = ?
                           and prompt_version = ?
                         order by updated_at desc, id desc
                         limit 1
                        """,
                scope,
                key,
                version);
        jdbcTemplate.update(
                """
                        insert into prompt_governance_runtime_cache_invalidation (
                            event_id, registry_scope, prompt_key, template_key, prompt_version, contract_version,
                            invalidation_reason, published_by, published_at, consumed
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                eventId,
                scope,
                key,
                release.isEmpty() ? null : release.get(0).get("template_key"),
                version,
                release.isEmpty() ? null : release.get(0).get("contract_version"),
                value(reason, "PQA governance release changed."),
                value(publishedBy, "system"),
                now,
                false);
        return new PromptGovernanceCacheInvalidation(
                eventId,
                safeScope(registryScope),
                promptKey.trim(),
                promptVersion.trim(),
                value(reason, "PQA governance release changed."),
                value(publishedBy, "system"),
                PromptQualityJdbcTimestamps.toText(now),
                false);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<PromptGovernanceCacheInvalidation> recentInvalidations(int limit) {
        int safeLimit = limit <= 0 ? 20 : Math.min(limit, 100);
        try {
            return jdbcTemplate.query(
                    """
                            select event_id, registry_scope, prompt_key, prompt_version,
                                   invalidation_reason, published_by, published_at, consumed
                              from prompt_governance_runtime_cache_invalidation
                             order by published_at desc, id desc
                             limit ?
                            """,
                    (rs, rowNum) -> new PromptGovernanceCacheInvalidation(
                            rs.getString("event_id"),
                            rs.getString("registry_scope"),
                            rs.getString("prompt_key"),
                            rs.getString("prompt_version"),
                            rs.getString("invalidation_reason"),
                            rs.getString("published_by"),
                            PromptQualityJdbcTimestamps.toText(rs.getTimestamp("published_at")),
                            rs.getBoolean("consumed")),
                    safeLimit);
        }
        catch (DataAccessException ignored) {
            return List.of();
        }
    }

    private String safeScope(String registryScope) {
        return StringUtils.hasText(registryScope)
                ? registryScope.trim().toUpperCase(Locale.ROOT)
                : DEFAULT_SCOPE;
    }

    private String require(String value, String name) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(name + " is required.");
        }
        return value.trim();
    }

    private String value(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }
}
