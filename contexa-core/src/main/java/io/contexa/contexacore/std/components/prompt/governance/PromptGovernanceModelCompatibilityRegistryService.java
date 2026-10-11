package io.contexa.contexacore.std.components.prompt.governance;


import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceBudgetProfileRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceModelCompatibilityRecord;
import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Transactional(transactionManager = "contexaTransactionManager")
public class PromptGovernanceModelCompatibilityRegistryService {

    private static final int DEFAULT_LIMIT = 16;
    private static final int MAX_LIMIT = 40;
    private static final String TOKEN_COUNTING_POLICY_KEY = "MODEL_AWARE_TOKEN_COUNTING_V1";
    private static final String CACHE_POLICY_KEY = "STRUCTURED_PROMPT_CACHE_BY_REQUEST_AND_BUDGET_V1";
    private static final String COMPACTION_POLICY_KEY = "LOSSLESS_PROMPT_OPTIMIZATION_V1";

    private final PromptGovernanceRegistryService promptGovernanceRegistryService;
    private final PromptGovernanceModelCompatibilityRepository modelCompatibilityRepository;
    private final PromptGovernanceBudgetProfileRepository budgetProfileRepository;

    public PromptGovernanceModelCompatibilityRegistryService(
            PromptGovernanceRegistryService promptGovernanceRegistryService,
            PromptGovernanceModelCompatibilityRepository modelCompatibilityRepository,
            PromptGovernanceBudgetProfileRepository budgetProfileRepository) {
        this.promptGovernanceRegistryService = promptGovernanceRegistryService;
        this.modelCompatibilityRepository = modelCompatibilityRepository;
        this.budgetProfileRepository = budgetProfileRepository;
    }

    /**
     * Records the declared model and budget profiles of each platform prompt. An existing row gets the declared content
     * again, but its compatibility, budget and policy states and its registration source are left as they are: they
     * belong to verification, not to the code declaration (version management PV-4).
     */
    public void syncPlatformRegistry() {
        promptGovernanceRegistryService.syncPlatformRegistry();
        for (PromptGovernanceDescriptor descriptor : PromptGovernanceRegistryService.platformStandardDescriptors()) {
            registerDeclaredProfiles(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, descriptor, "STANDARD_TEMPLATE_BOOTSTRAP");
        }
    }

    public void registerDeclaredProfiles(String registryScope, PromptGovernanceDescriptor descriptor, String registrationSource) {
        String safeScope = normalizeRegistryScope(registryScope);
        String safeSource = StringUtils.hasText(registrationSource) ? registrationSource.trim() : "UNSPECIFIED";
        for (String modelProfileKey : descriptor.supportedModelProfiles()) {
            upsertModelProfile(safeScope, descriptor, modelProfileKey, safeSource);
        }
        for (PromptBudgetProfile budgetProfile : PromptBudgetProfile.values()) {
            upsertBudgetProfile(safeScope, descriptor, budgetProfile, safeSource);
        }
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PromptGovernanceView.PromptGovernanceModelCompatibilitySnapshot getPlatformSnapshot(Integer limit) {
        return getSnapshot(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, limit);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PromptGovernanceView.PromptGovernanceModelCompatibilitySnapshot getSnapshot(String registryScope, Integer limit) {
        int safeLimit = PaginationHelper.safeLimit(limit, DEFAULT_LIMIT, MAX_LIMIT);
        String safeScope = normalizeRegistryScope(registryScope);
        List<PromptGovernanceModelCompatibilityRecord> modelRecords = currentModelRecords(
                modelCompatibilityRepository.findByRegistryScopeOrderByUpdatedAtDesc(safeScope));
        List<PromptGovernanceBudgetProfileRecord> budgetRecords = currentBudgetRecords(
                budgetProfileRepository.findByRegistryScopeOrderByUpdatedAtDesc(safeScope));

        Map<String, List<PromptGovernanceModelCompatibilityRecord>> modelsByPrompt = groupModelRecords(modelRecords);
        Map<String, List<PromptGovernanceBudgetProfileRecord>> budgetsByPrompt = groupBudgetRecords(budgetRecords);
        List<String> promptKeys = new ArrayList<>();
        promptKeys.addAll(modelsByPrompt.keySet());
        budgetsByPrompt.keySet().stream().filter(key -> !promptKeys.contains(key)).forEach(promptKeys::add);

        List<PromptGovernanceView.PromptGovernanceModelCompatibilityItem> prompts = promptKeys.stream()
                .map(promptIdentity -> toItem(
                        promptIdentity,
                        modelsByPrompt.getOrDefault(promptIdentity, List.of()),
                        budgetsByPrompt.getOrDefault(promptIdentity, List.of())))
                .sorted(Comparator.comparing(PromptGovernanceView.PromptGovernanceModelCompatibilityItem::updatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .limit(safeLimit)
                .toList();

        long declaredModelProfileCount = prompts.stream().mapToLong(item -> item.modelProfiles().size()).sum();
        long providerCompatibilityDeclaredCount = prompts.stream().filter(PromptGovernanceView.PromptGovernanceModelCompatibilityItem::providerCompatibilityDeclared).count();
        long budgetProfileGovernedCount = prompts.stream().filter(PromptGovernanceView.PromptGovernanceModelCompatibilityItem::budgetProfilesGoverned).count();
        long cachePolicyGovernedCount = prompts.stream().filter(PromptGovernanceView.PromptGovernanceModelCompatibilityItem::cachePolicyGoverned).count();
        long compactionPolicyGovernedCount = prompts.stream().filter(PromptGovernanceView.PromptGovernanceModelCompatibilityItem::compactionPolicyGoverned).count();
        String registryState = determineRegistryState(prompts);

        return new PromptGovernanceView.PromptGovernanceModelCompatibilitySnapshot(
                safeScope,
                prompts.size(),
                declaredModelProfileCount,
                providerCompatibilityDeclaredCount,
                budgetProfileGovernedCount,
                cachePolicyGovernedCount,
                compactionPolicyGovernedCount,
                registryState,
                buildRegistryFacts(prompts, registryState),
                prompts,
                LocalDateTime.now());
    }

    private void upsertModelProfile(
            String registryScope,
            PromptGovernanceDescriptor descriptor,
            String modelProfileKey,
            String registrationSource) {
        PromptGovernanceModelCompatibilityRecord record = modelCompatibilityRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionAndModelProfileKeyOrderByUpdatedAtDesc(
                        registryScope,
                        descriptor.promptKey(),
                        descriptor.promptVersion(),
                        modelProfileKey)
                .orElseGet(PromptGovernanceModelCompatibilityRecord::new);
        if (record.getId() == null) {
            record.setRegistryScope(registryScope);
            record.setPromptKey(descriptor.promptKey());
            record.setPromptVersion(descriptor.promptVersion());
            record.setModelProfileKey(modelProfileKey);
            record.setCompatibilityState("DECLARED_NOT_VERIFIED");
            record.setRegistrationSource(registrationSource);
        }
        record.setProfileCategory(resolveProfileCategory(modelProfileKey));
        record.setProviderScope(resolveProviderScope(modelProfileKey));
        record.setTokenCountingPolicyKey(TOKEN_COUNTING_POLICY_KEY);
        record.setCachePolicyKey(CACHE_POLICY_KEY);
        record.setCompactionPolicyKey(COMPACTION_POLICY_KEY);
        modelCompatibilityRepository.save(record);
    }

    private void upsertBudgetProfile(
            String registryScope,
            PromptGovernanceDescriptor descriptor,
            PromptBudgetProfile budgetProfile,
            String registrationSource) {
        PromptGovernanceBudgetProfileRecord record = budgetProfileRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionAndBudgetProfileKeyOrderByUpdatedAtDesc(
                        registryScope,
                        descriptor.promptKey(),
                        descriptor.promptVersion(),
                        budgetProfile.profileKey())
                .orElseGet(PromptGovernanceBudgetProfileRecord::new);
        if (record.getId() == null) {
            record.setRegistryScope(registryScope);
            record.setPromptKey(descriptor.promptKey());
            record.setPromptVersion(descriptor.promptVersion());
            record.setBudgetProfileKey(budgetProfile.profileKey());
            record.setBudgetState("DECLARED_IMPORTED");
            record.setCachePolicyState("DECLARED");
            record.setCompactionPolicyState("DECLARED");
            record.setRegistrationSource(registrationSource);
        }
        record.setMaxInputTokens(budgetProfile.maxInputTokens());
        record.setTokenCountingPolicyKey(TOKEN_COUNTING_POLICY_KEY);
        record.setCachePolicyKey(CACHE_POLICY_KEY);
        record.setCompactionPolicyKey(COMPACTION_POLICY_KEY);
        budgetProfileRepository.save(record);
    }

    private PromptGovernanceView.PromptGovernanceModelCompatibilityItem toItem(
            String promptIdentity,
            List<PromptGovernanceModelCompatibilityRecord> modelRecords,
            List<PromptGovernanceBudgetProfileRecord> budgetRecords) {
        String promptKey = promptKey(promptIdentity);
        String promptVersion = promptVersion(promptIdentity);
        List<PromptGovernanceView.PromptGovernanceModelProfileItem> modelProfiles = modelRecords.stream()
                .sorted(Comparator.comparing(PromptGovernanceModelCompatibilityRecord::getModelProfileKey))
                .map(record -> new PromptGovernanceView.PromptGovernanceModelProfileItem(
                        record.getModelProfileKey(),
                        record.getProfileCategory(),
                        record.getProviderScope(),
                        record.getCompatibilityState(),
                        record.getTokenCountingPolicyKey(),
                        record.getCachePolicyKey(),
                        record.getCompactionPolicyKey(),
                        record.getRegistrationSource()))
                .toList();
        List<PromptGovernanceView.PromptGovernanceBudgetProfileItem> budgetProfiles = budgetRecords.stream()
                .sorted(Comparator.comparing(
                        PromptGovernanceBudgetProfileRecord::getMaxInputTokens,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .map(record -> new PromptGovernanceView.PromptGovernanceBudgetProfileItem(
                        record.getBudgetProfileKey(),
                        safeInteger(record.getMaxInputTokens()),
                        record.getBudgetState(),
                        record.getTokenCountingPolicyKey(),
                        record.getCachePolicyKey(),
                        record.getCachePolicyState(),
                        record.getCompactionPolicyKey(),
                        record.getCompactionPolicyState(),
                        record.getRegistrationSource()))
                .toList();

        boolean providerCompatibilityDeclared = modelRecords.stream()
                .anyMatch(record -> "PROVIDER_COMPATIBILITY".equals(record.getProfileCategory()));
        boolean tokenCountingPolicyDeclared = !budgetRecords.isEmpty()
                && budgetRecords.stream().allMatch(record -> StringUtils.hasText(record.getTokenCountingPolicyKey()));
        boolean budgetProfilesGoverned = !budgetRecords.isEmpty();
        boolean cachePolicyGoverned = budgetProfilesGoverned
                && budgetRecords.stream().allMatch(record -> StringUtils.hasText(record.getCachePolicyKey())
                && StringUtils.hasText(record.getCachePolicyState()));
        boolean compactionPolicyGoverned = budgetProfilesGoverned
                && budgetRecords.stream().allMatch(record -> StringUtils.hasText(record.getCompactionPolicyKey())
                && StringUtils.hasText(record.getCompactionPolicyState()));
        String compatibilityState = determineCompatibilityState(
                providerCompatibilityDeclared,
                budgetProfilesGoverned,
                tokenCountingPolicyDeclared,
                cachePolicyGoverned,
                compactionPolicyGoverned);
        List<String> facts = List.of(
                String.format(Locale.ROOT, "modelProfiles=%d", modelProfiles.size()),
                String.format(Locale.ROOT, "budgetProfiles=%d", budgetProfiles.size()),
                String.format(Locale.ROOT, "providerCompatibilityDeclared=%s", providerCompatibilityDeclared),
                String.format(Locale.ROOT, "tokenCountingPolicyDeclared=%s", tokenCountingPolicyDeclared),
                String.format(Locale.ROOT, "cachePolicyGoverned=%s", cachePolicyGoverned),
                String.format(Locale.ROOT, "compactionPolicyGoverned=%s", compactionPolicyGoverned));
        String summary = String.format(
                Locale.ROOT,
                "Prompt %s version %s has %d model profiles and %d budget profiles with state %s.",
                promptKey,
                promptVersion,
                modelProfiles.size(),
                budgetProfiles.size(),
                compatibilityState);
        return new PromptGovernanceView.PromptGovernanceModelCompatibilityItem(
                promptKey,
                promptVersion,
                providerCompatibilityDeclared,
                tokenCountingPolicyDeclared,
                budgetProfilesGoverned,
                cachePolicyGoverned,
                compactionPolicyGoverned,
                compatibilityState,
                modelProfiles,
                budgetProfiles,
                latestUpdatedAt(modelRecords, budgetRecords),
                facts,
                summary);
    }

    private String determineCompatibilityState(
            boolean providerCompatibilityDeclared,
            boolean budgetProfilesGoverned,
            boolean tokenCountingPolicyDeclared,
            boolean cachePolicyGoverned,
            boolean compactionPolicyGoverned) {
        if (!providerCompatibilityDeclared) {
            return "PROVIDER_COMPATIBILITY_GAP";
        }
        if (!budgetProfilesGoverned) {
            return "BUDGET_PROFILE_GAP";
        }
        if (!tokenCountingPolicyDeclared) {
            return "TOKEN_COUNTING_GAP";
        }
        if (!cachePolicyGoverned) {
            return "CACHE_POLICY_GAP";
        }
        if (!compactionPolicyGoverned) {
            return "COMPACTION_POLICY_GAP";
        }
        return "DECLARED_GOVERNED";
    }

    private String determineRegistryState(List<PromptGovernanceView.PromptGovernanceModelCompatibilityItem> prompts) {
        if (prompts.isEmpty()) {
            return "EMPTY";
        }
        if (prompts.stream().anyMatch(item -> item.compatibilityState().endsWith("_GAP"))) {
            return "GOVERNANCE_GAP";
        }
        return "DECLARED_GOVERNED";
    }

    private List<String> buildRegistryFacts(List<PromptGovernanceView.PromptGovernanceModelCompatibilityItem> prompts, String registryState) {
        if (prompts.isEmpty()) {
            return List.of("No prompt model compatibility profiles are registered yet.");
        }
        long providerCompatibilityCount = prompts.stream().filter(PromptGovernanceView.PromptGovernanceModelCompatibilityItem::providerCompatibilityDeclared).count();
        long budgetGovernedCount = prompts.stream().filter(PromptGovernanceView.PromptGovernanceModelCompatibilityItem::budgetProfilesGoverned).count();
        return List.of(
                String.format(Locale.ROOT, "%d prompts have prompt model compatibility entries.", prompts.size()),
                String.format(Locale.ROOT, "%d prompts declare provider compatibility coverage.", providerCompatibilityCount),
                String.format(Locale.ROOT, "%d prompts have governed budget profiles.", budgetGovernedCount),
                String.format(Locale.ROOT, "Prompt model compatibility registry state is %s.", registryState));
    }

    private Map<String, List<PromptGovernanceModelCompatibilityRecord>> groupModelRecords(List<PromptGovernanceModelCompatibilityRecord> records) {
        Map<String, List<PromptGovernanceModelCompatibilityRecord>> grouped = new LinkedHashMap<>();
        for (PromptGovernanceModelCompatibilityRecord record : records) {
            grouped.computeIfAbsent(promptIdentity(record.getPromptKey(), record.getPromptVersion()), key -> new ArrayList<>()).add(record);
        }
        return grouped;
    }

    private Map<String, List<PromptGovernanceBudgetProfileRecord>> groupBudgetRecords(List<PromptGovernanceBudgetProfileRecord> records) {
        Map<String, List<PromptGovernanceBudgetProfileRecord>> grouped = new LinkedHashMap<>();
        for (PromptGovernanceBudgetProfileRecord record : records) {
            grouped.computeIfAbsent(promptIdentity(record.getPromptKey(), record.getPromptVersion()), key -> new ArrayList<>()).add(record);
        }
        return grouped;
    }

    private List<PromptGovernanceModelCompatibilityRecord> currentModelRecords(List<PromptGovernanceModelCompatibilityRecord> records) {
        Map<String, PromptGovernanceModelCompatibilityRecord> latest = new LinkedHashMap<>();
        records.stream()
                .sorted(Comparator.comparing(PromptGovernanceModelCompatibilityRecord::getUpdatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .forEach(record -> latest.putIfAbsent(modelRecordKey(record), record));
        return new ArrayList<>(latest.values());
    }

    private List<PromptGovernanceBudgetProfileRecord> currentBudgetRecords(List<PromptGovernanceBudgetProfileRecord> records) {
        Map<String, PromptGovernanceBudgetProfileRecord> latest = new LinkedHashMap<>();
        records.stream()
                .sorted(Comparator.comparing(PromptGovernanceBudgetProfileRecord::getUpdatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .forEach(record -> latest.putIfAbsent(budgetRecordKey(record), record));
        return new ArrayList<>(latest.values());
    }

    private String modelRecordKey(PromptGovernanceModelCompatibilityRecord record) {
        return promptIdentity(record.getPromptKey(), record.getPromptVersion()) + "::" + safeValue(record.getModelProfileKey(), "UNKNOWN");
    }

    private String budgetRecordKey(PromptGovernanceBudgetProfileRecord record) {
        return promptIdentity(record.getPromptKey(), record.getPromptVersion()) + "::" + safeValue(record.getBudgetProfileKey(), "UNKNOWN");
    }

    private String promptIdentity(String promptKey, String promptVersion) {
        return safeValue(promptKey, "UNKNOWN") + "::" + safeValue(promptVersion, "UNKNOWN");
    }

    private String promptKey(String promptIdentity) {
        int separator = promptIdentity.indexOf("::");
        return separator >= 0 ? promptIdentity.substring(0, separator) : promptIdentity;
    }

    private String promptVersion(String promptIdentity) {
        int separator = promptIdentity.indexOf("::");
        return separator >= 0 ? promptIdentity.substring(separator + 2) : "UNKNOWN";
    }

    private LocalDateTime latestUpdatedAt(
            List<PromptGovernanceModelCompatibilityRecord> modelRecords,
            List<PromptGovernanceBudgetProfileRecord> budgetRecords) {
        LocalDateTime latest = null;
        for (PromptGovernanceModelCompatibilityRecord record : modelRecords) {
            if (record.getUpdatedAt() != null && (latest == null || record.getUpdatedAt().isAfter(latest))) {
                latest = record.getUpdatedAt();
            }
        }
        for (PromptGovernanceBudgetProfileRecord record : budgetRecords) {
            if (record.getUpdatedAt() != null && (latest == null || record.getUpdatedAt().isAfter(latest))) {
                latest = record.getUpdatedAt();
            }
        }
        return latest;
    }

    private String resolveProfileCategory(String modelProfileKey) {
        String normalized = safeValue(modelProfileKey, "UNKNOWN").toUpperCase(Locale.ROOT);
        if (normalized.contains("COMPATIBLE")) {
            return "PROVIDER_COMPATIBILITY";
        }
        if (normalized.contains("JSON")) {
            return "OUTPUT_CONTRACT";
        }
        if (normalized.contains("RETRIEVAL")) {
            return "CONTEXT_POLICY";
        }
        return "INFERENCE_POLICY";
    }

    private String resolveProviderScope(String modelProfileKey) {
        String normalized = safeValue(modelProfileKey, "UNKNOWN").toUpperCase(Locale.ROOT);
        if (normalized.contains("OPENAI") || normalized.contains("ANTHROPIC") || normalized.contains("GEMINI")) {
            return "OPENAI|ANTHROPIC|GEMINI";
        }
        return "MODEL_AGNOSTIC";
    }

    private String normalizeRegistryScope(String registryScope) {
        return StringUtils.hasText(registryScope) ? registryScope.trim() : PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE;
    }

    private String safeValue(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    private int safeInteger(Integer value) {
        return value != null ? value : 0;
    }
}
