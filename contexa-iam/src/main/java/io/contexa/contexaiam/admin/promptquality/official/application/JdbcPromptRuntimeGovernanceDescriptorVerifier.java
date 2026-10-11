package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptRuntimeGovernanceDescriptorVerifier;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeGovernanceDescriptorVerificationResult;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public class JdbcPromptRuntimeGovernanceDescriptorVerifier
        implements PromptRuntimeGovernanceDescriptorVerifier {

    private static final String DEFAULT_REGISTRY_SCOPE = "PLATFORM_GLOBAL";
    private static final String METRIC_CODE = "MTR";
    private static final String SOURCE = "promptGovernance";

    /** Executing release states of every vocabulary (decision 1); a scoped canary row is preferred. */
    private static final String EXECUTING_STATES = PromptBundleState.sqlList(PromptBundleState.CANARY, PromptBundleState.ACTIVE);
    private static final String CANARY_STATES = PromptBundleState.sqlList(PromptBundleState.CANARY);

    private final JdbcTemplate jdbcTemplate;
    private final PromptQualityMessageResolver messageResolver;
    private final PromptBundleCatalog bundleCatalog;


    public JdbcPromptRuntimeGovernanceDescriptorVerifier(
            JdbcTemplate jdbcTemplate,
            PromptQualityMessageResolver messageResolver) {
        this(jdbcTemplate, messageResolver, PromptBundleCatalog.shared());
    }

    JdbcPromptRuntimeGovernanceDescriptorVerifier(
            JdbcTemplate jdbcTemplate,
            PromptQualityMessageResolver messageResolver,
            PromptBundleCatalog bundleCatalog) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
        this.bundleCatalog = Objects.requireNonNull(bundleCatalog, "bundleCatalog");
    }

    @Override
    public RuntimeGovernanceDescriptorVerificationResult verify(
            SealedEvidencePackage evidencePackage,
            Map<String, Object> promptMetadata) {
        return verifyPromptMetadata(promptMetadata);
    }

    private RuntimeGovernanceDescriptorVerificationResult verifyPromptMetadata(Map<String, Object> promptMetadata) {
        Map<String, Object> descriptor = descriptor(promptMetadata);
        List<RuntimeEvidenceCheckResult> checks = new ArrayList<>();
        String registryScope = text(descriptor, "registryScope");
        String promptKey = text(descriptor, "promptKey");
        String templateKey = text(descriptor, "templateKey");
        String promptVersion = text(descriptor, "promptVersion");
        String contractVersion = text(descriptor, "contractVersion");
        String releaseStatus = firstNonBlank(text(descriptor, "releaseStatus"), text(descriptor, "promptReleaseStatus"));
        String artifactHash = text(descriptor, "promptArtifactHashSha256");

        add(checks, "governance descriptor exists", "governanceDescriptor", descriptor.isEmpty() ? "missing" : "present", !descriptor.isEmpty());
        add(checks, "governance registry scope exists", "registryScope", value(registryScope), StringUtils.hasText(registryScope));
        add(checks, "governance prompt key exists", "promptKey", value(promptKey), StringUtils.hasText(promptKey));
        add(checks, "governance template key exists", "templateKey", value(templateKey), StringUtils.hasText(templateKey));
        add(checks, "governance prompt version exists", "promptVersion", value(promptVersion), StringUtils.hasText(promptVersion));
        add(checks, "governance contract version exists", "contractVersion", value(contractVersion), StringUtils.hasText(contractVersion));
        add(checks, "governance artifact hash exists", "promptArtifactHashSha256", value(artifactHash), StringUtils.hasText(artifactHash));

        RegistryRelease release = findActiveRelease(registryScope, promptKey, templateKey);
        add(checks, "core governance active release exists", "active registry row",
                release == null ? "missing" : release.identity(), release != null);
        if (release != null) {
            add(checks, "prompt version matches active governance release",
                    release.promptVersion(), value(promptVersion), same(release.promptVersion(), promptVersion));
            add(checks, "template key matches active governance release",
                    release.templateKey(), value(templateKey), same(release.templateKey(), templateKey));
            add(checks, "contract version matches active governance release",
                    release.contractVersion(), value(contractVersion), same(release.contractVersion(), contractVersion));
            add(checks, "artifact hash matches active governance release",
                    release.artifactHash(), value(artifactHash), same(release.artifactHash(), artifactHash));
            add(checks, "active governance release has approval reference",
                    "release approval reference",
                    value(release.releaseApprovalReference()),
                    StringUtils.hasText(release.releaseApprovalReference()));
            add(checks, "active governance release is approved for runtime",
                    "PRODUCTION or approved active state",
                    firstNonBlank(release.releaseStatus(), releaseStatus, "missing"),
                    runtimeApproved(release.releaseStatus()));
        }

        List<String> findings = checks.stream()
                .filter(check -> !check.pass())
                .map(check -> message(
                        "enterprise.pqa.runtimeGovernance.findingTpl",
                        labelFor(check.label()),
                        operatorValue(check.actualValue()),
                        targetFor(check.label())))
                .distinct()
                .toList();
        List<String> nextActions = findings.isEmpty()
                ? List.of()
                : List.of(message("enterprise.pqa.runtimeGovernance.action.reverify"));
        return new RuntimeGovernanceDescriptorVerificationResult(
                findings.isEmpty(),
                List.copyOf(checks),
                findings,
                nextActions);
    }

    /**
     * The release a judgment must match. When the prompt key has bundles in the build, only a version in the build can
     * be executing, so registry rows of other versions (for example problem resolution candidates recorded before
     * they moved to the policy set namespace) are never chosen (version management PV-15).
     */
    private RegistryRelease findActiveRelease(String registryScope, String promptKey, String templateKey) {
        if (!StringUtils.hasText(promptKey) || !StringUtils.hasText(templateKey)) {
            return null;
        }
        List<RegistryRelease> rows = jdbcTemplate.query(
                """
                        select registry_scope, prompt_key, template_key, prompt_version,
                               contract_version, prompt_artifact_hash_sha256, release_status,
                               release_approval_reference
                          from prompt_governance_registry
                         where registry_scope = ?
                           and prompt_key = ?
                           and template_key = ?
                           and upper(release_status) in (%s)
                          order by case when upper(release_status) in (%s) then 0 else 1 end,
                                   updated_at desc,
                                   id desc
                        """.formatted(EXECUTING_STATES, CANARY_STATES),
                this::mapRelease,
                firstNonBlank(registryScope, DEFAULT_REGISTRY_SCOPE),
                promptKey.trim(),
                templateKey.trim());
        boolean bundledKey = bundleCatalog.newest(promptKey.trim()).isPresent();
        return rows.stream()
                .filter(row -> !bundledKey || bundleCatalog.find(promptKey.trim(), row.promptVersion()).isPresent())
                .findFirst()
                .orElse(null);
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
                rs.getString("release_approval_reference"));
    }

    private Map<String, Object> descriptor(Map<String, Object> promptMetadata) {
        if (promptMetadata == null || promptMetadata.isEmpty()) {
            return Map.of();
        }
        Object nested = promptMetadata.get("governanceDescriptor");
        if (nested instanceof Map<?, ?> map) {
            Map<String, Object> result = new LinkedHashMap<>();
            map.forEach((key, value) -> result.put(String.valueOf(key), value));
            return result;
        }
        Map<String, Object> fallback = new LinkedHashMap<>();
        copy(promptMetadata, fallback, "registryScope");
        copy(promptMetadata, fallback, "promptKey");
        copy(promptMetadata, fallback, "templateKey");
        copy(promptMetadata, fallback, "promptVersion");
        copy(promptMetadata, fallback, "contractVersion");
        copy(promptMetadata, fallback, "releaseStatus");
        copy(promptMetadata, fallback, "promptReleaseStatus");
        copy(promptMetadata, fallback, "releaseApprovalReference");
        copy(promptMetadata, fallback, "promptReleaseApprovalReference");
        copy(promptMetadata, fallback, "promptArtifactHashSha256");
        return fallback;
    }

    private void copy(Map<String, Object> source, Map<String, Object> target, String key) {
        Object value = source.get(key);
        if (value != null && StringUtils.hasText(String.valueOf(value))) {
            target.put(key, value);
        }
    }

    private void add(List<RuntimeEvidenceCheckResult> checks, String label, String expected, String actual, boolean pass) {
        checks.add(new RuntimeEvidenceCheckResult(METRIC_CODE, label, expected, actual, pass, SOURCE));
    }

    private String labelFor(String label) {
        String normalized = value(label).toLowerCase(Locale.ROOT);
        if (normalized.contains("descriptor")) return message("enterprise.pqa.promptConsistency.label.governanceDescriptor");
        if (normalized.contains("registry scope")) return message("enterprise.pqa.promptConsistency.label.governanceRegistryScope");
        if (normalized.contains("prompt key")) return message("enterprise.pqa.promptConsistency.label.governancePromptKey");
        if (normalized.contains("template key")) return message("enterprise.pqa.promptConsistency.label.governanceTemplateKey");
        if (normalized.contains("prompt version")) return message("enterprise.pqa.promptConsistency.label.governancePromptVersion");
        if (normalized.contains("contract version")) return message("enterprise.pqa.promptConsistency.label.governanceContractVersion");
        if (normalized.contains("artifact hash")) return message("enterprise.pqa.promptConsistency.label.governanceArtifactHash");
        if (normalized.contains("active release")) return message("enterprise.pqa.promptConsistency.label.governanceActiveRelease");
        if (normalized.contains("approval reference")) return message("enterprise.pqa.promptConsistency.label.governanceApprovalReference");
        if (normalized.contains("approved for runtime")) return message("enterprise.pqa.promptConsistency.label.governanceRuntimeApproved");
        return message("enterprise.pqa.runtimeGovernance.label.default");
    }

    private String targetFor(String label) {
        String normalized = value(label).toLowerCase(Locale.ROOT);
        if (normalized.contains("prompt version")) return "promptGovernance.promptVersion";
        if (normalized.contains("approval reference")) return "promptGovernance.releaseApprovalReference";
        if (normalized.contains("template key")) return "promptGovernance.templateKey";
        if (normalized.contains("contract version")) return "promptGovernance.contractVersion";
        if (normalized.contains("artifact hash")) return "promptGovernance.promptArtifactHashSha256";
        if (normalized.contains("registry scope")) return "promptGovernance.registryScope";
        if (normalized.contains("prompt key")) return "promptGovernance.promptKey";
        if (normalized.contains("approved for runtime")) return "promptGovernance.releaseStatus";
        return "promptGovernance.governanceDescriptor";
    }

    private String operatorValue(String actual) {
        String value = value(actual);
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "missing" -> message("enterprise.pqa.runtimeGovernance.value.missing");
            case "present" -> message("enterprise.pqa.runtimeGovernance.value.present");
            default -> value;
        };
    }

    private String message(String key, Object... args) {
        return messageResolver.resolveRequired(key, args);
    }

    private boolean runtimeApproved(String releaseStatus) {
        return PromptBundleState.isExecuting(releaseStatus);
    }

    private boolean same(String left, String right) {
        return value(left).equalsIgnoreCase(value(right));
    }

    private String text(Map<String, Object> map, String key) {
        Object value = map == null ? null : map.get(key);
        return value == null ? null : String.valueOf(value).trim();
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String item : values) {
            if (StringUtils.hasText(item)) {
                return item.trim();
            }
        }
        return null;
    }

    private String value(String value) {
        return StringUtils.hasText(value) ? value.trim() : "missing";
    }

    private record RegistryRelease(
            String registryScope,
            String promptKey,
            String templateKey,
            String promptVersion,
            String contractVersion,
            String artifactHash,
            String releaseStatus,
            String releaseApprovalReference) {

        private String identity() {
            return registryScope + "/" + promptKey + "@" + promptVersion;
        }
    }
}
