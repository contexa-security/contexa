package io.contexa.contexacore.std.components.prompt.governance;


import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

@Transactional(transactionManager = "contexaTransactionManager")
public class PromptGovernanceRegistryService {

    public static final String PLATFORM_GLOBAL_SCOPE = "PLATFORM_GLOBAL";
    private static final int DEFAULT_LIMIT = 16;
    private static final int MAX_LIMIT = 40;
    private static final List<PromptGovernanceDescriptor> PLATFORM_STANDARD_DESCRIPTORS = List.of(
            SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE
    );

    private final PromptGovernanceRegistryRepository repository;
    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    public PromptGovernanceRegistryService(PromptGovernanceRegistryRepository repository) {
        this.repository = repository;
    }

    public PromptRegistrationReceipt registerPromptArtifact(
            String registryScope,
            PromptGovernanceDescriptor descriptor,
            String registrationSource) {
        String safeRegistryScope = normalizeRegistryScope(registryScope);
        String safeRegistrationSource = StringUtils.hasText(registrationSource)
                ? registrationSource.trim()
                : "UNSPECIFIED";
        PromptGovernanceRegistryRecord record = repository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        safeRegistryScope,
                        descriptor.promptKey(),
                        descriptor.promptVersion())
                .orElseGet(PromptGovernanceRegistryRecord::new);
        boolean created = record.getId() == null;
        boolean contentChanged = applyContentFields(record, descriptor);
        if (created) {
            // The declaration is only the first value of the operational fields; after that they belong to the
            // release workflow and a code sync must not overwrite them (version management PV-4).
            record.setRegistryScope(safeRegistryScope);
            record.setPromptKey(descriptor.promptKey());
            record.setPromptVersion(descriptor.promptVersion());
            record.setReleaseStatus(PromptBundleState.fromReleaseStatus(descriptor.releaseStatus()).name());
            record.setReleaseApprovalReference(descriptor.releaseApprovalReference());
            record.setEvaluationBaselineReference(descriptor.evaluationBaselineReference());
            record.setRollbackPromptVersion(descriptor.rollbackPromptVersion());
            record.setRegistrationSource(safeRegistrationSource);
        }
        if (!created && !contentChanged) {
            return receipt(safeRegistryScope, record, false);
        }
        applyTimestamps(record, created);
        PromptGovernanceRegistryRecord saved = repository.save(record);
        return receipt(safeRegistryScope, saved, created);
    }

    private PromptRegistrationReceipt receipt(String registryScope, PromptGovernanceRegistryRecord record, boolean created) {
        return new PromptRegistrationReceipt(
                registryScope,
                record.getPromptKey(),
                record.getPromptVersion(),
                record.getReleaseStatus(),
                created,
                LocalDateTime.now());
    }

    /** Writes the fields that the code owns and returns whether any of them changed. */
    private boolean applyContentFields(PromptGovernanceRegistryRecord record, PromptGovernanceDescriptor descriptor) {
        String modelProfilesJson = writeJsonList(descriptor.supportedModelProfiles());
        String artifactHash = computeArtifactHash(descriptor);
        boolean changed = !Objects.equals(record.getTemplateKey(), descriptor.templateKey())
                || !Objects.equals(record.getContractVersion(), descriptor.contractVersion())
                || !Objects.equals(record.getPromptArtifactHashSha256(), artifactHash)
                || !Objects.equals(record.getOwner(), descriptor.owner())
                || !Objects.equals(record.getChangeSummary(), descriptor.changeSummary())
                || !Objects.equals(record.getTemplateClassName(), descriptor.templateClassName())
                || !Objects.equals(record.getSupportedModelProfilesJson(), modelProfilesJson);
        record.setTemplateKey(descriptor.templateKey());
        record.setContractVersion(descriptor.contractVersion());
        record.setPromptArtifactHashSha256(artifactHash);
        record.setOwner(descriptor.owner());
        record.setChangeSummary(descriptor.changeSummary());
        record.setTemplateClassName(descriptor.templateClassName());
        record.setSupportedModelProfilesJson(modelProfilesJson);
        return changed;
    }

    public void syncPlatformRegistry() {
        for (PromptGovernanceDescriptor descriptor : PLATFORM_STANDARD_DESCRIPTORS) {
            registerPromptArtifact(PLATFORM_GLOBAL_SCOPE, descriptor, "STANDARD_TEMPLATE_BOOTSTRAP");
        }
    }

    public static List<PromptGovernanceDescriptor> platformStandardDescriptors() {
        return PLATFORM_STANDARD_DESCRIPTORS;
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PromptGovernanceView.PromptGovernanceRegistrySnapshot getPlatformSnapshot(Integer limit) {
        return getSnapshot(PLATFORM_GLOBAL_SCOPE, limit);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PromptGovernanceView.PromptGovernanceRegistrySnapshot getSnapshot(String registryScope, Integer limit) {
        int safeLimit = PaginationHelper.safeLimit(limit, DEFAULT_LIMIT, MAX_LIMIT);
        List<PromptGovernanceRegistryRecord> records = currentRecords(
                repository.findByRegistryScopeOrderByUpdatedAtDesc(normalizeRegistryScope(registryScope)));
        long productionCount = records.stream().filter(record -> PromptBundleState.is(record.getReleaseStatus(), PromptBundleState.ACTIVE)).count();
        long approvalLinkedCount = records.stream().filter(this::hasReleaseApprovalReference).count();
        long evalLinkedCount = records.stream().filter(this::hasEvalReference).count();
        long rollbackReadyCount = records.stream().filter(this::hasRollbackReference).count();
        long modelCompatibleCount = records.stream().filter(this::hasModelProfiles).count();
        List<PromptGovernanceView.PromptGovernanceRegistryItem> prompts = records.stream()
                .sorted(Comparator
                        .comparing((PromptGovernanceRegistryRecord record) -> PromptBundleState.is(record.getReleaseStatus(), PromptBundleState.ACTIVE))
                        .reversed()
                        .thenComparing(PromptGovernanceRegistryRecord::getUpdatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .limit(safeLimit)
                .map(this::toItem)
                .toList();
        return new PromptGovernanceView.PromptGovernanceRegistrySnapshot(
                normalizeRegistryScope(registryScope),
                records.size(),
                productionCount,
                approvalLinkedCount,
                evalLinkedCount,
                rollbackReadyCount,
                modelCompatibleCount,
                determineRegistryState(records, productionCount),
                prompts,
                LocalDateTime.now());
    }

    private PromptGovernanceView.PromptGovernanceRegistryItem toItem(PromptGovernanceRegistryRecord record) {
        List<String> modelProfiles = readJsonList(record.getSupportedModelProfilesJson());
        boolean releaseApproved = hasReleaseApprovalReference(record);
        boolean evalLinked = hasEvalReference(record);
        boolean rollbackReady = hasRollbackReference(record);
        boolean modelProfilesDeclared = !modelProfiles.isEmpty();
        List<String> governanceFacts = List.of(
                String.format(Locale.ROOT, "releaseStatus=%s", safeValue(record.getReleaseStatus(), "UNKNOWN")),
                String.format(Locale.ROOT, "releaseApprovalLinked=%s", releaseApproved),
                String.format(Locale.ROOT, "evalLinked=%s", evalLinked),
                String.format(Locale.ROOT, "rollbackReady=%s", rollbackReady),
                String.format(Locale.ROOT, "modelProfilesDeclared=%s", modelProfilesDeclared),
                String.format(Locale.ROOT, "registrationSource=%s", safeValue(record.getRegistrationSource(), "UNSPECIFIED"))
        );
        String summary = String.format(
                Locale.ROOT,
                "Prompt %s version %s is %s with evalLinked=%s, releaseApproved=%s, rollbackReady=%s, modelProfilesDeclared=%s.",
                safeValue(record.getPromptKey(), "unknown"),
                safeValue(record.getPromptVersion(), "unknown"),
                safeValue(record.getReleaseStatus(), "UNKNOWN"),
                evalLinked,
                releaseApproved,
                rollbackReady,
                modelProfilesDeclared);
        return new PromptGovernanceView.PromptGovernanceRegistryItem(
                record.getPromptKey(),
                record.getTemplateKey(),
                record.getPromptVersion(),
                record.getContractVersion(),
                record.getPromptArtifactHashSha256(),
                record.getReleaseStatus(),
                record.getOwner(),
                record.getReleaseApprovalReference(),
                record.getEvaluationBaselineReference(),
                record.getRollbackPromptVersion(),
                releaseApproved,
                evalLinked,
                rollbackReady,
                modelProfilesDeclared,
                modelProfiles,
                record.getTemplateClassName(),
                record.getRegistrationSource(),
                record.getUpdatedAt(),
                governanceFacts,
                summary);
    }

    private String determineRegistryState(List<PromptGovernanceRegistryRecord> records, long productionCount) {
        if (records.isEmpty()) {
            return "EMPTY";
        }
        boolean governanceGap = records.stream()
                .filter(record -> PromptBundleState.is(record.getReleaseStatus(), PromptBundleState.ACTIVE))
                .anyMatch(record -> !hasReleaseApprovalReference(record)
                        || !hasEvalReference(record)
                        || !hasRollbackReference(record)
                        || !hasModelProfiles(record));
        if (governanceGap) {
            return "PRODUCTION_GOVERNANCE_GAP";
        }
        boolean canaryActive = records.stream().anyMatch(record -> PromptBundleState.is(record.getReleaseStatus(), PromptBundleState.CANARY));
        if (canaryActive) {
            return "CANARY_ACTIVE";
        }
        if (productionCount > 0) {
            return "CONTROLLED_PRODUCTION";
        }
        return "REGISTERED_ONLY";
    }

    private List<PromptGovernanceRegistryRecord> currentRecords(List<PromptGovernanceRegistryRecord> records) {
        Map<String, PromptGovernanceRegistryRecord> latestByPrompt = new LinkedHashMap<>();
        records.stream()
                .sorted(Comparator
                        .comparing(PromptGovernanceRegistryRecord::getUpdatedAt, Comparator.nullsLast(Comparator.reverseOrder()))
                        .thenComparing(PromptGovernanceRegistryRecord::getCreatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .forEach(record -> latestByPrompt.putIfAbsent(currentRecordKey(record), record));
        return new ArrayList<>(latestByPrompt.values());
    }

    private String currentRecordKey(PromptGovernanceRegistryRecord record) {
        return safeValue(record.getPromptKey(), "UNKNOWN");
    }

    private boolean hasReleaseApprovalReference(PromptGovernanceRegistryRecord record) {
        return StringUtils.hasText(record.getReleaseApprovalReference());
    }

    private boolean hasEvalReference(PromptGovernanceRegistryRecord record) {
        return StringUtils.hasText(record.getEvaluationBaselineReference());
    }

    private boolean hasRollbackReference(PromptGovernanceRegistryRecord record) {
        return StringUtils.hasText(record.getRollbackPromptVersion());
    }

    private boolean hasModelProfiles(PromptGovernanceRegistryRecord record) {
        return !readJsonList(record.getSupportedModelProfilesJson()).isEmpty();
    }

    private String normalizeRegistryScope(String registryScope) {
        return StringUtils.hasText(registryScope) ? registryScope.trim() : PLATFORM_GLOBAL_SCOPE;
    }

    private String writeJsonList(List<String> values) {
        try {
            return objectMapper.writeValueAsString(values == null ? List.of() : values);
        }
        catch (JsonProcessingException ex) {
            throw new IllegalStateException("Failed to serialize prompt governance model profiles", ex);
        }
    }

    private List<String> readJsonList(String json) {
        if (!StringUtils.hasText(json)) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, objectMapper.getTypeFactory().constructCollectionType(List.class, String.class));
        }
        catch (JsonProcessingException ex) {
            return List.of();
        }
    }

    private String computeArtifactHash(PromptGovernanceDescriptor descriptor) {
        return descriptor.artifactHashSha256();
    }

    private String safeValue(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    private void applyTimestamps(PromptGovernanceRegistryRecord record, boolean created) {
        LocalDateTime now = LocalDateTime.now();
        if (created && record.getCreatedAt() == null) {
            record.setCreatedAt(now);
        }
        if (record.getUpdatedAt() == null || !created) {
            record.setUpdatedAt(now);
        }
    }

    public record PromptRegistrationReceipt(
            String registryScope,
            String promptKey,
            String promptVersion,
            String releaseStatus,
            boolean created,
            LocalDateTime acceptedAt) {
    }
}
