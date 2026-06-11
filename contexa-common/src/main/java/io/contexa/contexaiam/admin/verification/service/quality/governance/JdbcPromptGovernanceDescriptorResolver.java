package io.contexa.contexaiam.admin.verification.service.quality.governance;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptorResolution;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptorResolver;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class JdbcPromptGovernanceDescriptorResolver implements PromptGovernanceDescriptorResolver {

    private static final String DEFAULT_SCOPE = "PLATFORM_GLOBAL";
    private static final long CACHE_TTL_MILLIS = 60_000L;
    private static final long INVALIDATION_POLL_INTERVAL_MILLIS = 5_000L;

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final long cacheTtlMillis;
    private final long invalidationPollIntervalMillis;
    private final ConcurrentMap<CacheKey, CacheEntry> cache = new ConcurrentHashMap<>();
    private volatile long lastInvalidationPollEpochMs;
    private volatile long lastInvalidationId;

    public JdbcPromptGovernanceDescriptorResolver(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this(jdbcTemplate, objectMapper, CACHE_TTL_MILLIS, INVALIDATION_POLL_INTERVAL_MILLIS);
    }

    public JdbcPromptGovernanceDescriptorResolver(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            long cacheTtlMillis,
            long invalidationPollIntervalMillis) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
        this.cacheTtlMillis = cacheTtlMillis <= 0 ? CACHE_TTL_MILLIS : cacheTtlMillis;
        this.invalidationPollIntervalMillis = Math.max(0, invalidationPollIntervalMillis);
    }

    @Override
    public PromptGovernanceDescriptorResolution resolve(
            PromptGovernanceDescriptor fallbackDescriptor,
            PromptGovernanceResolutionContext context) {
        if (fallbackDescriptor == null) {
            throw new IllegalArgumentException("fallbackDescriptor is required.");
        }
        promptInvalidationPoll();
        CacheKey key = cacheKey(fallbackDescriptor, context);
        long now = System.currentTimeMillis();
        CacheEntry cached = cache.get(key);
        if (cached != null && !cached.expired(now, cacheTtlMillis)) {
            return cached.resolution();
        }
        PromptGovernanceDescriptorResolution resolution = findActiveRelease(key, fallbackDescriptor, context);
        cache.put(key, new CacheEntry(resolution, now));
        return resolution;
    }

    private PromptGovernanceDescriptorResolution findActiveRelease(
            CacheKey key,
            PromptGovernanceDescriptor fallbackDescriptor,
            PromptGovernanceResolutionContext context) {
        try {
            List<RegistryRelease> releases = jdbcTemplate.query(
                    """
                            select registry_scope, prompt_key, template_key, prompt_version,
                                   contract_version, prompt_artifact_hash_sha256, release_status,
                                   owner_name, release_approval_reference, evaluation_baseline_reference,
                                   rollback_prompt_version, change_summary, template_class_name,
                                   supported_model_profiles_json, updated_at
                              from prompt_governance_registry
                             where registry_scope = ?
                               and prompt_key = ?
                               and template_key = ?
                               and upper(release_status) in (
                                   'ACTIVE_FOR_SCOPE', 'PRODUCTION', 'ACTIVE',
                                   'RELEASED', 'RUNTIME_APPROVED', 'PRODUCTION_APPROVED'
                               )
                             order by case upper(release_status)
                                          when 'ACTIVE_FOR_SCOPE' then 0
                                          when 'PRODUCTION' then 1
                                          else 2
                                      end,
                                      updated_at desc,
                                      id desc
                             limit 1
                            """,
                    this::mapRelease,
                    key.registryScope(),
                    key.promptKey(),
                    key.templateKey());
            if (releases.isEmpty()) {
                return fallback(fallbackDescriptor, context, "MISS");
            }
            return releaseResolution(fallbackDescriptor, releases.get(0));
        }
        catch (DataAccessException ignored) {
            return fallback(fallbackDescriptor, context, "STORE_UNAVAILABLE");
        }
    }

    private PromptGovernanceDescriptorResolution releaseResolution(
            PromptGovernanceDescriptor fallbackDescriptor,
            RegistryRelease release) {
        PromptGovernanceDescriptor descriptor = new PromptGovernanceDescriptor(
                value(release.promptKey(), fallbackDescriptor.promptKey()),
                value(release.templateKey(), fallbackDescriptor.templateKey()),
                value(release.promptVersion(), fallbackDescriptor.promptVersion()),
                value(release.contractVersion(), fallbackDescriptor.contractVersion()),
                descriptorReleaseStatus(release.releaseStatus()),
                value(release.owner(), fallbackDescriptor.owner()),
                value(release.releaseApprovalReference(), fallbackDescriptor.releaseApprovalReference()),
                value(release.evaluationBaselineReference(), fallbackDescriptor.evaluationBaselineReference()),
                value(release.rollbackPromptVersion(), fallbackDescriptor.rollbackPromptVersion()),
                value(release.changeSummary(), fallbackDescriptor.changeSummary()),
                supportedModelProfiles(release.supportedModelProfilesJson(), fallbackDescriptor.supportedModelProfiles()),
                value(release.templateClassName(), fallbackDescriptor.templateClassName()));
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("registryScope", value(release.registryScope(), DEFAULT_SCOPE));
        metadata.put("releaseStatus", value(release.releaseStatus(), descriptor.releaseStatus().name()));
        metadata.put("promptReleaseStatus", value(release.releaseStatus(), descriptor.releaseStatus().name()));
        metadata.put("releaseApprovalReference", value(release.releaseApprovalReference(), descriptor.releaseApprovalReference()));
        metadata.put("promptReleaseApprovalReference", value(release.releaseApprovalReference(), descriptor.releaseApprovalReference()));
        metadata.put("promptArtifactHashSha256", value(release.artifactHash(), descriptor.artifactHashSha256()));
        metadata.put("coreRegistryReleaseStatus", value(release.releaseStatus(), descriptor.releaseStatus().name()));
        metadata.put("governanceResolutionSource", "CORE_PROMPT_GOVERNANCE_REGISTRY");
        metadata.put("promptGovernanceCacheState", "ACTIVE_RELEASE");
        metadata.put("governanceRegistryUpdatedAt", release.updatedAt() != null ? release.updatedAt().toInstant().toString() : null);
        return new PromptGovernanceDescriptorResolution(descriptor, metadata);
    }

    private PromptGovernanceDescriptorResolution fallback(
            PromptGovernanceDescriptor fallbackDescriptor,
            PromptGovernanceResolutionContext context,
            String cacheState) {
        Map<String, Object> metadata = new LinkedHashMap<>(
                PromptGovernanceDescriptorResolution.fallback(fallbackDescriptor, context).supplementalMetadata());
        metadata.put("promptGovernanceCacheState", cacheState);
        return new PromptGovernanceDescriptorResolution(fallbackDescriptor, metadata);
    }

    private void promptInvalidationPoll() {
        long now = System.currentTimeMillis();
        if (now - lastInvalidationPollEpochMs < invalidationPollIntervalMillis) {
            return;
        }
        synchronized (this) {
            if (now - lastInvalidationPollEpochMs < invalidationPollIntervalMillis) {
                return;
            }
            try {
                List<InvalidationEvent> events = jdbcTemplate.query(
                        """
                                select id, registry_scope, prompt_key
                                  from prompt_governance_runtime_cache_invalidation
                                 where id > ?
                                 order by id asc
                                 limit 200
                                """,
                        (rs, rowNum) -> new InvalidationEvent(
                                rs.getLong("id"),
                                normalizeScope(rs.getString("registry_scope")),
                                normalizeIdentifier(rs.getString("prompt_key"))),
                        lastInvalidationId);
                for (InvalidationEvent event : events) {
                    cache.keySet().removeIf(key -> key.registryScope().equals(event.registryScope())
                            && key.promptKey().equals(event.promptKey()));
                    lastInvalidationId = Math.max(lastInvalidationId, event.id());
                }
            }
            catch (DataAccessException ignored) {
                // Resolver must never break runtime prompt generation when the enterprise ledger is unavailable.
            }
            finally {
                lastInvalidationPollEpochMs = now;
            }
        }
    }

    private RegistryRelease mapRelease(ResultSet rs, int rowNum) throws SQLException {
        return new RegistryRelease(
                rs.getString("registry_scope"),
                rs.getString("prompt_key"),
                rs.getString("template_key"),
                rs.getString("prompt_version"),
                rs.getString("contract_version"),
                rs.getString("prompt_artifact_hash_sha256"),
                rs.getString("release_status"),
                rs.getString("owner_name"),
                rs.getString("release_approval_reference"),
                rs.getString("evaluation_baseline_reference"),
                rs.getString("rollback_prompt_version"),
                rs.getString("change_summary"),
                rs.getString("template_class_name"),
                rs.getString("supported_model_profiles_json"),
                rs.getTimestamp("updated_at"));
    }

    private CacheKey cacheKey(PromptGovernanceDescriptor fallbackDescriptor, PromptGovernanceResolutionContext context) {
        return new CacheKey(
                normalizeScope(context != null ? context.registryScope() : null),
                normalizeIdentifier(context != null ? context.promptKey() : fallbackDescriptor.promptKey()),
                normalizeIdentifier(context != null ? context.templateKey() : fallbackDescriptor.templateKey()));
    }

    private PromptReleaseStatus descriptorReleaseStatus(String releaseStatus) {
        String normalized = normalizeStatus(releaseStatus);
        return switch (normalized) {
            case "DRAFT" -> PromptReleaseStatus.DRAFT;
            case "EVAL_ONLY" -> PromptReleaseStatus.EVAL_ONLY;
            case "CANARY" -> PromptReleaseStatus.CANARY;
            case "ROLLED_BACK" -> PromptReleaseStatus.ROLLED_BACK;
            case "RETIRED" -> PromptReleaseStatus.RETIRED;
            default -> PromptReleaseStatus.PRODUCTION;
        };
    }

    private List<String> supportedModelProfiles(String json, List<String> fallback) {
        if (!StringUtils.hasText(json)) {
            return fallback != null ? fallback : List.of();
        }
        try {
            List<String> values = objectMapper.readValue(json, new TypeReference<>() {
            });
            return values == null ? List.of() : values.stream()
                    .filter(StringUtils::hasText)
                    .map(String::trim)
                    .toList();
        }
        catch (Exception ignored) {
            return fallback != null ? fallback : List.of();
        }
    }

    private String normalizeScope(String value) {
        return StringUtils.hasText(value)
                ? value.trim().toUpperCase(Locale.ROOT)
                : DEFAULT_SCOPE;
    }

    private String normalizeIdentifier(String value) {
        return StringUtils.hasText(value)
                ? value.trim()
                : "";
    }

    private String normalizeStatus(String value) {
        return StringUtils.hasText(value)
                ? value.trim().toUpperCase(Locale.ROOT)
                : "";
    }

    private String value(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    private record CacheKey(String registryScope, String promptKey, String templateKey) {
    }

    private record CacheEntry(PromptGovernanceDescriptorResolution resolution, long createdAtEpochMs) {
        private boolean expired(long nowEpochMs, long ttlMillis) {
            return nowEpochMs - createdAtEpochMs > ttlMillis;
        }
    }

    private record InvalidationEvent(long id, String registryScope, String promptKey) {
    }

    private record RegistryRelease(
            String registryScope,
            String promptKey,
            String templateKey,
            String promptVersion,
            String contractVersion,
            String artifactHash,
            String releaseStatus,
            String owner,
            String releaseApprovalReference,
            String evaluationBaselineReference,
            String rollbackPromptVersion,
            String changeSummary,
            String templateClassName,
            String supportedModelProfilesJson,
            Timestamp updatedAt) {
    }
}
