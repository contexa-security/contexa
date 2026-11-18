package io.contexa.contexaiam.admin.promptquality.governance;

import java.util.Arrays;
import java.util.Objects;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptorResolution;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptorResolver;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRelease;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * The prompt governance registry at runtime: the descriptor of a release (its status, approval and artifact hash for
 * the execution record) and the registry implementation of the bundle selector (W3-16, version management function
 * 4), which runs the release of the request's scope by its state and canary share.
 *
 * <p>The executing releases (CANARY and ACTIVE) of a scope, prompt key and template key are read once and cached for
 * both, whatever the version (PV-2). A cache invalidation event clears them at the next poll; a read that fails is
 * logged as an error when it starts failing, and the build default runs meanwhile (PV-23).
 */
public class JdbcPromptGovernanceDescriptorResolver implements PromptGovernanceDescriptorResolver {

    private static final Logger log = LoggerFactory.getLogger(JdbcPromptGovernanceDescriptorResolver.class);

    /** Executing release states of every vocabulary (decision 1). */
    private static final String EXECUTING_STATES = PromptBundleState.sqlList(PromptBundleState.SHADOW,
            PromptBundleState.CANARY, PromptBundleState.ACTIVE);

    private static final String DEFAULT_SCOPE = "PLATFORM_GLOBAL";
    private static final int WHOLE_SCOPE_PERCENT = 100;
    private static final long CACHE_TTL_MILLIS = 60_000L;
    private static final long INVALIDATION_POLL_INTERVAL_MILLIS = 5_000L;

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final long cacheTtlMillis;
    private final long invalidationPollIntervalMillis;
    private final ConcurrentMap<CacheKey, CacheEntry> cache = new ConcurrentHashMap<>();
    private volatile long lastInvalidationPollEpochMs;
    private volatile long lastInvalidationId;
    private volatile boolean releaseReadFailing;
    private volatile boolean invalidationReadFailing;
    private volatile boolean shadowSettingsReadFailing;

    public JdbcPromptGovernanceDescriptorResolver(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this(jdbcTemplate, objectMapper, CACHE_TTL_MILLIS, INVALIDATION_POLL_INTERVAL_MILLIS);
    }

    JdbcPromptGovernanceDescriptorResolver(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            long cacheTtlMillis,
            long invalidationPollIntervalMillis) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
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
        Releases releases = releases(new CacheKey(
                normalizeScope(context != null ? context.registryScope() : null),
                normalizeIdentifier(context != null ? context.promptKey() : fallbackDescriptor.promptKey()),
                normalizeIdentifier(context != null ? context.templateKey() : fallbackDescriptor.templateKey())));
        if (releases.unavailable()) {
            return fallback(fallbackDescriptor, context, "STORE_UNAVAILABLE");
        }
        return releases.release(normalizeIdentifier(fallbackDescriptor.promptVersion()),
                        normalizeIdentifier(fallbackDescriptor.contractVersion()))
                .map(release -> releaseResolution(fallbackDescriptor, release))
                .orElseGet(() -> fallback(fallbackDescriptor, context, "MISS"));
    }

    /**
     * The registry selector (plan 3.4): the label of the request's scope, else the label of the platform. In a scope a
     * canary release runs for the requests of its target tenants and resource families whose requester falls inside its
     * share ({@code canary_percent}; no share is the whole scope); the others run the scope's latest active release. A
     * scope whose releases choose nothing for the request (a shadow alone, a canary the request is outside of) leaves
     * the choice to the platform (K45); without a choice the build default runs. A release is named as a bundle or as a
     * version of the database ({@code v2.0}) alike.
     */
    public PromptBundleSelector registrySelector() {
        return new PromptBundleSelector() {
            @Override
            public PromptBundleSelection select(PromptGovernanceResolutionContext context, String subjectKey) {
                return JdbcPromptGovernanceDescriptorResolver.this.select(context, subjectKey);
            }

            @Override
            public PromptBundleSelection shadow(PromptGovernanceResolutionContext context, String subjectKey) {
                PromptShadowRelease shadow = shadowRelease(context, subjectKey);
                return shadow.present() ? new PromptBundleSelection(shadow.version(), PromptBundleSelectionSource.SHADOW)
                        : PromptBundleSelection.none();
            }

            @Override
            public PromptShadowRelease shadowRelease(PromptGovernanceResolutionContext context, String subjectKey) {
                return JdbcPromptGovernanceDescriptorResolver.this.shadow(context);
            }
        };
    }

    /**
     * W6-9 (P6-CHANGE-6), plan 3.4: the shadow release of the request's scope, else of the platform, the candidate a
     * shadow run draws, with the sample share and daily limit its row sets; none without one.
     */
    private PromptShadowRelease shadow(PromptGovernanceResolutionContext context) {
        if (context == null || !StringUtils.hasText(context.promptKey())) {
            return PromptShadowRelease.none();
        }
        Releases releases = releases(cacheKey(context));
        for (List<RegistryRelease> scope : releases.selectionScopes()) {
            Optional<RegistryRelease> shadow = scope.stream()
                    .filter(release -> PromptBundleState.is(release.releaseStatus(), PromptBundleState.SHADOW))
                    .findFirst();
            if (shadow.isPresent()) {
                return new PromptShadowRelease(shadow.get().promptVersion(), shadow.get().shadowSamplePercent(),
                        shadow.get().shadowDailyLimit());
            }
        }
        return PromptShadowRelease.none();
    }

    private PromptBundleSelection select(PromptGovernanceResolutionContext context, String subjectKey) {
        if (context == null || !StringUtils.hasText(context.promptKey())) {
            return PromptBundleSelection.none();
        }
        Releases releases = releases(cacheKey(context));
        for (List<RegistryRelease> scope : releases.selectionScopes()) {
            Optional<PromptBundleSelection> label = label(scope, context, subjectKey);
            if (label.isPresent()) {
                return label.get();
            }
        }
        return PromptBundleSelection.none();
    }

    /** The release one scope chooses for the request: its canary when the request falls inside it, else its active one. */
    private static Optional<PromptBundleSelection> label(List<RegistryRelease> scope,
                                                         PromptGovernanceResolutionContext context, String subjectKey) {
        Optional<RegistryRelease> canary = scope.stream()
                .filter(release -> PromptBundleState.is(release.releaseStatus(), PromptBundleState.CANARY))
                .findFirst();
        if (canary.isPresent() && insideTargets(canary.get(), context)
                && insideShare(canary.get().canaryPercent(), subjectKey)) {
            return Optional.of(new PromptBundleSelection(canary.get().promptVersion(), PromptBundleSelectionSource.CANARY));
        }
        return scope.stream()
                .filter(release -> PromptBundleState.is(release.releaseStatus(), PromptBundleState.ACTIVE))
                .findFirst()
                .map(release -> new PromptBundleSelection(release.promptVersion(), PromptBundleSelectionSource.REGISTRY));
    }

    private static CacheKey cacheKey(PromptGovernanceResolutionContext context) {
        return new CacheKey(normalizeScope(context.registryScope()), normalizeIdentifier(context.promptKey()),
                normalizeIdentifier(context.templateKey()));
    }

    /**
     * W6-9 (P6-CHANGE-6): a canary with target tenants or resource families runs only for a request of one of them; a
     * resource family is the start of the request's resource address or its resource id.
     */
    private static boolean insideTargets(RegistryRelease canary, PromptGovernanceResolutionContext context) {
        boolean tenant = canary.canaryTenants().isEmpty() || canary.canaryTenants().contains(context.tenantId());
        boolean resource = canary.canaryResourceFamilies().isEmpty() || canary.canaryResourceFamilies().stream()
                .anyMatch(family -> (context.resourceUrl() != null && context.resourceUrl().startsWith(family))
                        || family.equals(context.resourceId()));
        return tenant && resource;
    }

    private static List<String> targets(String value) {
        if (!StringUtils.hasText(value)) {
            return List.of();
        }
        return Arrays.stream(value.split(",")).map(String::trim).filter(StringUtils::hasText).toList();
    }

    /**
     * Plan 3.4: whether the requester falls inside the canary's share. The same requester always falls on the same
     * side: the share is drawn by the hash of the requester's key, which is the same on every server. A request without
     * a requester (a screen asking what the scope runs) is inside only a canary of the whole scope.
     */
    static boolean insideShare(Integer canaryPercent, String subjectKey) {
        int percent = canaryPercent == null ? WHOLE_SCOPE_PERCENT : Math.max(0, Math.min(WHOLE_SCOPE_PERCENT, canaryPercent));
        if (!StringUtils.hasText(subjectKey)) {
            return percent >= WHOLE_SCOPE_PERCENT;
        }
        return Math.floorMod(subjectKey.hashCode(), WHOLE_SCOPE_PERCENT) < percent;
    }

    private Releases releases(CacheKey key) {
        promptInvalidationPoll();
        long now = System.currentTimeMillis();
        CacheEntry cached = cache.get(key);
        if (cached != null && !cached.expired(now, cacheTtlMillis)) {
            return cached.releases();
        }
        Releases releases = readReleases(key);
        cache.put(key, new CacheEntry(releases, now));
        return releases;
    }

    private Releases readReleases(CacheKey key) {
        try {
            List<RegistryRelease> rows = jdbcTemplate.query(
                    """
                            select registry_scope, prompt_key, template_key, prompt_version,
                                   contract_version, prompt_artifact_hash_sha256, release_status,
                                   owner_name, release_approval_reference, evaluation_baseline_reference,
                                   rollback_prompt_version, change_summary, template_class_name,
                                   supported_model_profiles_json, canary_percent, canary_tenants,
                                   canary_resource_families, updated_at
                              from ctxa_prompt_governance_registry
                             where registry_scope in (?, ?)
                               and prompt_key = ?
                               and template_key = ?
                               and upper(release_status) in (%s)
                             order by updated_at desc,
                                      id desc
                            """.formatted(EXECUTING_STATES),
                    this::mapRelease,
                    key.registryScope(),
                    DEFAULT_SCOPE,
                    key.promptKey(),
                    key.templateKey());
            releaseReadFailing = false;
            rows = withShadowSettings(rows);
            return new Releases(
                    rows.stream().filter(row -> key.registryScope().equals(normalizeScope(row.registryScope()))).toList(),
                    rows.stream().filter(row -> DEFAULT_SCOPE.equals(normalizeScope(row.registryScope()))).toList(),
                    false);
        }
        catch (DataAccessException exception) {
            if (!releaseReadFailing) {
                releaseReadFailing = true;
                log.error("Prompt governance registry releases could not be read; the build default prompt bundle runs"
                        + " until the registry can be read", exception);
            }
            return new Releases(List.of(), List.of(), true);
        }
    }

    /**
     * Plan 3.4: the sample share and daily limit the rows of shadow releases set, read apart from the releases: a
     * schema without the two columns keeps its releases, and its shadow runs keep the configured share and limit.
     */
    private List<RegistryRelease> withShadowSettings(List<RegistryRelease> rows) {
        if (rows.stream().noneMatch(row -> PromptBundleState.is(row.releaseStatus(), PromptBundleState.SHADOW))) {
            return rows;
        }
        List<RegistryRelease> read = new ArrayList<>(rows.size());
        for (RegistryRelease row : rows) {
            if (!PromptBundleState.is(row.releaseStatus(), PromptBundleState.SHADOW)) {
                read.add(row);
                continue;
            }
            try {
                List<Integer[]> settings = jdbcTemplate.query("select shadow_sample_percent, shadow_daily_limit from"
                                + " ctxa_prompt_governance_registry where registry_scope = ? and prompt_key = ? and"
                                + " prompt_version = ?",
                        (rs, rowNum) -> new Integer[] {rs.getObject(1, Integer.class), rs.getObject(2, Integer.class)},
                        row.registryScope(), row.promptKey(), row.promptVersion());
                Integer[] setting = settings.isEmpty() ? new Integer[2] : settings.get(0);
                read.add(row.withShadow(setting[0], setting[1]));
                shadowSettingsReadFailing = false;
            }
            catch (DataAccessException exception) {
                if (!shadowSettingsReadFailing) {
                    shadowSettingsReadFailing = true;
                    log.warn("The sample share and daily limit of the shadow release {} could not be read; the shadow"
                            + " run keeps its configured ones", row.promptVersion(), exception);
                }
                read.add(row);
            }
        }
        return List.copyOf(read);
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
                                select id, registry_scope, prompt_key, template_key
                                  from ctxa_prompt_governance_runtime_cache_invalidation
                                 where id > ?
                                 order by id asc
                                 limit 200
                                """,
                        (rs, rowNum) -> new InvalidationEvent(
                                rs.getLong("id"),
                                normalizeScope(rs.getString("registry_scope")),
                                normalizeIdentifier(rs.getString("prompt_key")),
                                normalizeIdentifier(rs.getString("template_key"))),
                        lastInvalidationId);
                for (InvalidationEvent event : events) {
                    cache.keySet().removeIf(event::clears);
                    lastInvalidationId = Math.max(lastInvalidationId, event.id());
                }
                invalidationReadFailing = false;
            }
            catch (DataAccessException exception) {
                if (!invalidationReadFailing) {
                    invalidationReadFailing = true;
                    log.error("Prompt governance cache invalidations could not be read; cached registry releases"
                            + " change only when they expire after {} ms", cacheTtlMillis, exception);
                }
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
                rs.getObject("canary_percent", Integer.class),
                targets(rs.getString("canary_tenants")),
                targets(rs.getString("canary_resource_families")),
                rs.getTimestamp("updated_at"),
                null,
                null);
    }

    private PromptReleaseStatus descriptorReleaseStatus(String releaseStatus) {
        return PromptBundleState.fromStoredValue(releaseStatus)
                .map(PromptBundleState::releaseStatus)
                .orElse(PromptReleaseStatus.PRODUCTION);
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

    private static String normalizeScope(String value) {
        return StringUtils.hasText(value)
                ? value.trim().toUpperCase(Locale.ROOT)
                : DEFAULT_SCOPE;
    }

    private static String normalizeIdentifier(String value) {
        return StringUtils.hasText(value)
                ? value.trim()
                : "";
    }

    private String value(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    private record CacheKey(String registryScope, String promptKey, String templateKey) {
    }

    private record CacheEntry(Releases releases, long createdAtEpochMs) {
        private boolean expired(long nowEpochMs, long ttlMillis) {
            return nowEpochMs - createdAtEpochMs > ttlMillis;
        }
    }

    /**
     * The executing releases of a request's scope and of the platform scope, latest first; unavailable when the
     * registry could not be read.
     */
    private record Releases(List<RegistryRelease> requestScope, List<RegistryRelease> platformScope, boolean unavailable) {

        /**
         * The releases a selection draws from, in order (plan 3.4): the request scope's own, then the platform's; a
         * scope that chooses nothing for a request leaves the choice to the next.
         */
        private List<List<RegistryRelease>> selectionScopes() {
            return List.of(requestScope, platformScope);
        }

        /** The release of a version and contract, in the request scope first and then in the platform scope. */
        private Optional<RegistryRelease> release(String promptVersion, String contractVersion) {
            return requestScope.stream().filter(release -> release.is(promptVersion, contractVersion)).findFirst()
                    .or(() -> platformScope.stream().filter(release -> release.is(promptVersion, contractVersion)).findFirst());
        }
    }

    /**
     * An invalidation clears the cached releases of its prompt key: of its scope, or of every scope when it is the
     * platform scope; of its template key, or of every template key when it has none (PV-23).
     */
    private record InvalidationEvent(long id, String registryScope, String promptKey, String templateKey) {

        private boolean clears(CacheKey key) {
            return promptKey.equals(key.promptKey())
                    && (DEFAULT_SCOPE.equals(registryScope) || registryScope.equals(key.registryScope()))
                    && (templateKey.isEmpty() || templateKey.equals(key.templateKey()));
        }
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
            Integer canaryPercent,
            List<String> canaryTenants,
            List<String> canaryResourceFamilies,
            Timestamp updatedAt,
            Integer shadowSamplePercent,
            Integer shadowDailyLimit) {

        private boolean is(String version, String contract) {
            return version.equals(normalizeIdentifier(promptVersion)) && contract.equals(normalizeIdentifier(contractVersion));
        }

        private RegistryRelease withShadow(Integer samplePercent, Integer dailyLimit) {
            return new RegistryRelease(registryScope, promptKey, templateKey, promptVersion, contractVersion, artifactHash,
                    releaseStatus, owner, releaseApprovalReference, evaluationBaselineReference, rollbackPromptVersion,
                    changeSummary, templateClassName, supportedModelProfilesJson, canaryPercent, canaryTenants,
                    canaryResourceFamilies, updatedAt, samplePercent, dailyLimit);
        }
    }
}
