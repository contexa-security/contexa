package io.contexa.contexacore.std.components.prompt.governance;


import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceEvaluationRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleManifest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
public class PromptGovernanceEmpiricalEvalService {

    private static final int DEFAULT_LIMIT = 16;
    private static final int MAX_LIMIT = 40;
    // N-GOV-2: the families an evaluation must cover when the bundle manifest declares none of its own.
    private static final List<String> DEFAULT_REQUIRED_SCENARIO_FAMILIES = List.of(
            "PROMPT_INJECTION",
            "TOOL_MISUSE",
            "MEMORY_POISONING");

    private final PromptGovernanceRegistryRepository registryRepository;
    private final PromptGovernanceEvaluationRecordRepository evaluationRepository;
    private final PromptBundleCatalog bundleCatalog;
    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    public PromptGovernanceEmpiricalEvalService(
            PromptGovernanceRegistryRepository registryRepository,
            PromptGovernanceEvaluationRecordRepository evaluationRepository) {
        this(registryRepository, evaluationRepository, PromptBundleCatalog.shared());
    }

    /** N-GOV-2: the bundles of this build, whose manifests may declare the scenario families of their evaluation. */
    public PromptGovernanceEmpiricalEvalService(
            PromptGovernanceRegistryRepository registryRepository,
            PromptGovernanceEvaluationRecordRepository evaluationRepository,
            PromptBundleCatalog bundleCatalog) {
        this.registryRepository = registryRepository;
        this.evaluationRepository = evaluationRepository;
        this.bundleCatalog = bundleCatalog;
    }

    /**
     * N-GOV-2: the scenario families an evaluation of a bundle must cover. A manifest that declares
     * {@code evaluationScenarioFamilies} sets them (a prompt that calls no tools has no tool misuse to cover); a
     * manifest that declares none, or a version without a manifest, needs the default families.
     */
    public static List<String> requiredScenarioFamilies(PromptBundleManifest manifest) {
        List<String> declared = manifest == null
                ? List.of() : normalizeFamilyNames(manifest.evaluationScenarioFamilies());
        return declared.isEmpty() ? DEFAULT_REQUIRED_SCENARIO_FAMILIES : declared;
    }

    /** N-GOV-3: the required families an evaluation left uncovered, in the required order. */
    public static List<String> uncoveredScenarioFamilies(List<String> requiredFamilies, List<String> coveredFamilies) {
        List<String> covered = normalizeFamilyNames(coveredFamilies);
        return requiredFamilies.stream().filter(family -> !covered.contains(family)).toList();
    }

    public EvalRegistrationReceipt recordEvaluation(
            String registryScope,
            String promptKey,
            String promptVersion,
            String evaluationReference,
            String evaluationMode,
            List<String> coveredScenarioFamilies,
            String promptInjectionState,
            String latencyGateState,
            String costGateState,
            String actor,
            String summary) {
        return recordEvaluation(registryScope, promptKey, promptVersion, evaluationReference, evaluationMode,
                coveredScenarioFamilies, promptInjectionState, latencyGateState, costGateState, actor, summary, null,
                null);
    }

    /**
     * W6-8 (PV-5, PV-6): an evaluation that names the bundle hash it ran and the runs it counted; the release gate
     * takes it as the evidence of that bundle only.
     */
    public EvalRegistrationReceipt recordEvaluation(
            String registryScope,
            String promptKey,
            String promptVersion,
            String evaluationReference,
            String evaluationMode,
            List<String> coveredScenarioFamilies,
            String promptInjectionState,
            String latencyGateState,
            String costGateState,
            String actor,
            String summary,
            String bundleHash,
            String runReference) {
        String safeScope = normalizeRegistryScope(registryScope);
        PromptGovernanceRegistryRecord registryRecord = registryRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        safeScope,
                        requireText(promptKey, "promptKey"),
                        requireText(promptVersion, "promptVersion"))
                .orElseThrow(() -> new IllegalArgumentException("Unknown prompt governance artifact: " + promptKey + "@" + promptVersion));

        // N-GOV-2: the families this bundle's evaluation must cover come from its manifest, or are the default ones.
        List<String> requiredFamilies = requiredScenarioFamilies(
                registryRecord.getPromptKey(), registryRecord.getPromptVersion());
        List<String> normalizedFamilies = normalizeScenarioFamilies(coveredScenarioFamilies, requiredFamilies);
        String normalizedPromptInjectionState = normalizeGateState(promptInjectionState, "promptInjectionState");
        String normalizedLatencyGateState = normalizeGateState(latencyGateState, "latencyGateState");
        String normalizedCostGateState = normalizeGateState(costGateState, "costGateState");

        int coveredScenarioCount = normalizedFamilies.size();
        int requiredScenarioCount = requiredFamilies.size();
        String scenarioCoverageState = determineScenarioCoverageState(coveredScenarioCount, requiredScenarioCount);
        String empiricalEvidenceState = coveredScenarioCount > 0 ? "SATISFIED" : "MISSING";
        String tevvGateState = determineTevvGateState(
                normalizedPromptInjectionState,
                normalizedLatencyGateState,
                normalizedCostGateState,
                scenarioCoverageState);
        String qualityGateState = determineQualityGateState(tevvGateState);
        String evaluationState = determineEvaluationState(tevvGateState);

        PromptGovernanceEvaluationRecord record = evaluationRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        safeScope,
                        registryRecord.getPromptKey(),
                        registryRecord.getPromptVersion())
                .orElseGet(PromptGovernanceEvaluationRecord::new);
        record.setRegistryScope(safeScope);
        record.setPromptKey(registryRecord.getPromptKey());
        record.setPromptVersion(registryRecord.getPromptVersion());
        record.setEvaluationReference(requireText(evaluationReference, "evaluationReference"));
        record.setEvaluationMode(requireText(evaluationMode, "evaluationMode"));
        record.setEvaluationState(evaluationState);
        record.setEmpiricalEvidenceState(empiricalEvidenceState);
        record.setPromptInjectionState(normalizedPromptInjectionState);
        record.setScenarioCoverageState(scenarioCoverageState);
        record.setCoveredScenarioCount(coveredScenarioCount);
        record.setRequiredScenarioCount(requiredScenarioCount);
        record.setCoveredScenarioFamiliesJson(writeJsonList(normalizedFamilies));
        record.setTevvGateState(tevvGateState);
        record.setQualityGateState(qualityGateState);
        record.setLatencyGateState(normalizedLatencyGateState);
        record.setCostGateState(normalizedCostGateState);
        record.setEvaluationSummary(normalizeSummary(summary, tevvGateState, scenarioCoverageState));
        record.setEvaluatedBy(requireText(actor, "actor"));
        record.setRegistrationSource("PROMPT_EMPIRICAL_EVAL_WORKFLOW");
        record.setBundleHash(bundleHash);
        record.setRunReference(runReference);
        PromptGovernanceEvaluationRecord saved = evaluationRepository.save(record);
        return new EvalRegistrationReceipt(
                safeScope,
                saved.getPromptKey(),
                saved.getPromptVersion(),
                saved.getEvaluationState(),
                saved.getTevvGateState(),
                saved.getUpdatedAt());
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PromptGovernanceView.PromptGovernanceEmpiricalEvalSnapshot getPlatformSnapshot(Integer limit) {
        return getSnapshot(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, limit);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PromptGovernanceView.PromptGovernanceEmpiricalEvalSnapshot getSnapshot(String registryScope, Integer limit) {
        int safeLimit = PaginationHelper.safeLimit(limit, DEFAULT_LIMIT, MAX_LIMIT);
        String safeScope = normalizeRegistryScope(registryScope);
        Map<String, PromptGovernanceEvaluationRecord> evaluationIndex = latestEvaluations(
                evaluationRepository.findByRegistryScopeOrderByUpdatedAtDesc(safeScope));
        List<PromptGovernanceRegistryRecord> registryRecords = registryRepository.findByRegistryScopeOrderByUpdatedAtDesc(safeScope);
        List<PromptGovernanceView.PromptGovernanceEmpiricalEvalItem> prompts = latestRegistries(registryRecords).stream()
                .limit(safeLimit)
                .map(record -> toItem(record, evaluationIndex.get(key(record.getPromptKey(), record.getPromptVersion()))))
                .toList();

        long productionReadyCount = prompts.stream().filter(item -> "READY_FOR_PRODUCTION".equals(item.tevvGateState())).count();
        long canaryReadyCount = prompts.stream().filter(item -> "READY_FOR_CANARY".equals(item.tevvGateState())).count();
        long evidenceGapCount = prompts.stream().filter(item -> "EVIDENCE_GAP".equals(item.tevvGateState()) || "NOT_READY".equals(item.tevvGateState())).count();
        long promptInjectionBlockedCount = prompts.stream().filter(item -> "PROMPT_INJECTION_BLOCK".equals(item.tevvGateState())).count();
        long nonFunctionalBlockedCount = prompts.stream().filter(item -> "NON_FUNCTIONAL_BLOCK".equals(item.tevvGateState())).count();
        String evalPortfolioState = determinePortfolioState(productionReadyCount, canaryReadyCount, evidenceGapCount, promptInjectionBlockedCount, nonFunctionalBlockedCount);

        return new PromptGovernanceView.PromptGovernanceEmpiricalEvalSnapshot(
                safeScope,
                prompts.size(),
                productionReadyCount,
                canaryReadyCount,
                evidenceGapCount,
                promptInjectionBlockedCount,
                nonFunctionalBlockedCount,
                evalPortfolioState,
                buildPortfolioFacts(prompts, evalPortfolioState),
                prompts,
                LocalDateTime.now());
    }

    private PromptGovernanceView.PromptGovernanceEmpiricalEvalItem toItem(
            PromptGovernanceRegistryRecord registryRecord,
            PromptGovernanceEvaluationRecord evaluationRecord) {
        List<String> families = evaluationRecord != null ? readJsonList(evaluationRecord.getCoveredScenarioFamiliesJson()) : List.of();
        // N-GOV-3: the families the bundle requires and the required ones the evaluation left uncovered, by name.
        List<String> required = requiredScenarioFamilies(registryRecord.getPromptKey(), registryRecord.getPromptVersion());
        List<String> facts = new ArrayList<>();
        facts.add(String.format(
                Locale.ROOT,
                "Prompt %s version %s is currently %s.",
                registryRecord.getPromptKey(),
                registryRecord.getPromptVersion(),
                registryRecord.getReleaseStatus()));
        if (evaluationRecord == null) {
            facts.add("Empirical evaluation has not been recorded in enterprise control plane.");
            return new PromptGovernanceView.PromptGovernanceEmpiricalEvalItem(
                    registryRecord.getPromptKey(),
                    registryRecord.getPromptVersion(),
                    null,
                    null,
                    "NOT_RECORDED",
                    "MISSING",
                    "NOT_VERIFIED",
                    "NOT_RECORDED",
                    0,
                    required.size(),
                    List.of(),
                    required,
                    required,
                    "NOT_READY",
                    "NOT_VERIFIED",
                    "NOT_VERIFIED",
                    "NOT_VERIFIED",
                    null,
                    registryRecord.getUpdatedAt(),
                    List.copyOf(facts),
                    "Empirical evaluation has not been recorded yet.");
        }
        facts.add(String.format(
                Locale.ROOT,
                "Evaluation state=%s, empiricalEvidenceState=%s, scenarioCoverage=%d/%d.",
                evaluationRecord.getEvaluationState(),
                evaluationRecord.getEmpiricalEvidenceState(),
                evaluationRecord.getCoveredScenarioCount(),
                evaluationRecord.getRequiredScenarioCount()));
        facts.add(String.format(
                Locale.ROOT,
                "promptInjection=%s, latency=%s, cost=%s, tevvGate=%s.",
                evaluationRecord.getPromptInjectionState(),
                evaluationRecord.getLatencyGateState(),
                evaluationRecord.getCostGateState(),
                evaluationRecord.getTevvGateState()));
        if (!families.isEmpty()) {
            facts.add("Covered scenario families: " + String.join(", ", families));
        }
        return new PromptGovernanceView.PromptGovernanceEmpiricalEvalItem(
                registryRecord.getPromptKey(),
                registryRecord.getPromptVersion(),
                evaluationRecord.getEvaluationReference(),
                evaluationRecord.getEvaluationMode(),
                evaluationRecord.getEvaluationState(),
                evaluationRecord.getEmpiricalEvidenceState(),
                evaluationRecord.getPromptInjectionState(),
                evaluationRecord.getScenarioCoverageState(),
                evaluationRecord.getCoveredScenarioCount(),
                evaluationRecord.getRequiredScenarioCount(),
                families,
                required,
                uncoveredScenarioFamilies(required, families),
                evaluationRecord.getTevvGateState(),
                evaluationRecord.getQualityGateState(),
                evaluationRecord.getLatencyGateState(),
                evaluationRecord.getCostGateState(),
                evaluationRecord.getEvaluatedBy(),
                evaluationRecord.getUpdatedAt(),
                List.copyOf(facts),
                evaluationRecord.getEvaluationSummary());
    }

    public record EvalRegistrationReceipt(
            String registryScope,
            String promptKey,
            String promptVersion,
            String evaluationState,
            String tevvGateState,
            LocalDateTime recordedAt) {
    }

    private String determineScenarioCoverageState(int coveredScenarioCount, int requiredScenarioCount) {
        if (coveredScenarioCount <= 0) {
            return "MISSING";
        }
        if (coveredScenarioCount >= requiredScenarioCount) {
            return "COMPLETE";
        }
        return "PARTIAL";
    }

    private String determineTevvGateState(
            String promptInjectionState,
            String latencyGateState,
            String costGateState,
            String scenarioCoverageState) {
        if ("FAILED".equals(promptInjectionState)) {
            return "PROMPT_INJECTION_BLOCK";
        }
        if ("FAILED".equals(latencyGateState) || "FAILED".equals(costGateState)) {
            return "NON_FUNCTIONAL_BLOCK";
        }
        if ("COMPLETE".equals(scenarioCoverageState)
                && "PASSED".equals(promptInjectionState)
                && "PASSED".equals(latencyGateState)
                && "PASSED".equals(costGateState)) {
            return "READY_FOR_PRODUCTION";
        }
        if ("PARTIAL".equals(scenarioCoverageState)
                && !"FAILED".equals(promptInjectionState)
                && !"FAILED".equals(latencyGateState)
                && !"FAILED".equals(costGateState)) {
            return "READY_FOR_CANARY";
        }
        if ("MISSING".equals(scenarioCoverageState)) {
            return "EVIDENCE_GAP";
        }
        return "NOT_READY";
    }

    private String determineQualityGateState(String tevvGateState) {
        return switch (tevvGateState) {
            case "READY_FOR_PRODUCTION", "READY_FOR_CANARY" -> "PASSED";
            case "PROMPT_INJECTION_BLOCK", "NON_FUNCTIONAL_BLOCK" -> "FAILED";
            default -> "INCOMPLETE";
        };
    }

    private String determineEvaluationState(String tevvGateState) {
        return switch (tevvGateState) {
            case "READY_FOR_PRODUCTION" -> "PASSED";
            case "READY_FOR_CANARY" -> "CANARY_ONLY";
            case "PROMPT_INJECTION_BLOCK", "NON_FUNCTIONAL_BLOCK" -> "FAILED";
            default -> "COLLECTING";
        };
    }

    private String determinePortfolioState(
            long productionReadyCount,
            long canaryReadyCount,
            long evidenceGapCount,
            long promptInjectionBlockedCount,
            long nonFunctionalBlockedCount) {
        if (promptInjectionBlockedCount > 0) {
            return "PROMPT_INJECTION_BLOCK";
        }
        if (nonFunctionalBlockedCount > 0) {
            return "NON_FUNCTIONAL_BLOCK";
        }
        if (productionReadyCount > 0) {
            return "READY_FOR_PRODUCTION";
        }
        if (canaryReadyCount > 0) {
            return "READY_FOR_CANARY";
        }
        return evidenceGapCount > 0 ? "EVIDENCE_GAP" : "COLLECTING";
    }

    private List<String> buildPortfolioFacts(List<PromptGovernanceView.PromptGovernanceEmpiricalEvalItem> prompts, String evalPortfolioState) {
        if (prompts.isEmpty()) {
            return List.of("No prompt empirical evaluation items are registered yet.");
        }
        long totalCoveredScenarios = prompts.stream().mapToLong(PromptGovernanceView.PromptGovernanceEmpiricalEvalItem::coveredScenarioCount).sum();
        return List.of(
                String.format(Locale.ROOT, "%d prompt versions are currently tracked for empirical evaluation.", prompts.size()),
                String.format(Locale.ROOT, "Total covered scenarios across tracked prompts is %d.", totalCoveredScenarios),
                String.format(Locale.ROOT, "Empirical eval portfolio state is %s.", evalPortfolioState)
        );
    }

    private List<PromptGovernanceRegistryRecord> latestRegistries(List<PromptGovernanceRegistryRecord> records) {
        Map<String, PromptGovernanceRegistryRecord> latest = new LinkedHashMap<>();
        records.stream()
                .sorted(Comparator.comparing(PromptGovernanceRegistryRecord::getUpdatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .forEach(record -> latest.putIfAbsent(key(record.getPromptKey(), record.getPromptVersion()), record));
        return List.copyOf(latest.values());
    }

    private Map<String, PromptGovernanceEvaluationRecord> latestEvaluations(List<PromptGovernanceEvaluationRecord> records) {
        Map<String, PromptGovernanceEvaluationRecord> latest = new LinkedHashMap<>();
        records.stream()
                .sorted(Comparator.comparing(PromptGovernanceEvaluationRecord::getUpdatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .forEach(record -> latest.putIfAbsent(key(record.getPromptKey(), record.getPromptVersion()), record));
        return latest;
    }

    private String key(String promptKey, String promptVersion) {
        return promptKey + "::" + promptVersion;
    }

    private List<String> requiredScenarioFamilies(String promptKey, String promptVersion) {
        return requiredScenarioFamilies(bundleCatalog.find(promptKey, promptVersion).orElse(null));
    }

    /** The covered families the bundle requires; a family it does not require is not counted (N-GOV-2). */
    private List<String> normalizeScenarioFamilies(List<String> coveredScenarioFamilies, List<String> requiredFamilies) {
        return normalizeFamilyNames(coveredScenarioFamilies).stream()
                .filter(requiredFamilies::contains)
                .toList();
    }

    private static List<String> normalizeFamilyNames(List<String> families) {
        if (families == null || families.isEmpty()) {
            return List.of();
        }
        return families.stream()
                .filter(StringUtils::hasText)
                .map(value -> value.trim().toUpperCase(Locale.ROOT))
                .distinct()
                .sorted()
                .toList();
    }

    private String normalizeGateState(String value, String fieldName) {
        String normalized = requireText(value, fieldName).trim().toUpperCase(Locale.ROOT);
        if (!List.of("PASSED", "FAILED", "NOT_VERIFIED").contains(normalized)) {
            throw new IllegalArgumentException(fieldName + " must be one of PASSED, FAILED, NOT_VERIFIED");
        }
        return normalized;
    }

    private String normalizeSummary(String summary, String tevvGateState, String scenarioCoverageState) {
        if (StringUtils.hasText(summary)) {
            return summary.trim();
        }
        return String.format(
                Locale.ROOT,
                "Prompt empirical eval is %s with scenario coverage %s.",
                tevvGateState,
                scenarioCoverageState);
    }

    private String normalizeRegistryScope(String registryScope) {
        return StringUtils.hasText(registryScope)
                ? registryScope.trim()
                : PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE;
    }

    private String requireText(String value, String fieldName) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(fieldName + " is required.");
        }
        return value.trim();
    }

    private String writeJsonList(List<String> values) {
        try {
            return objectMapper.writeValueAsString(values == null ? List.of() : values);
        }
        catch (JsonProcessingException ex) {
            throw new IllegalStateException("Failed to serialize covered scenario families", ex);
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
}
