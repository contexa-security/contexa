package io.contexa.contexacore.autonomous.context.resolver;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.ReasoningMemoryProfile;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;

/**
 * Resolves ReasoningMemoryProfile from metadata.
 * Extracted from DefaultCanonicalSecurityContextProvider - all business logic preserved.
 */
public class ReasoningMemoryProfileResolver extends AbstractProfileResolver<ReasoningMemoryProfile> {

    @Override
    protected ReasoningMemoryProfile doResolve(Map<String, Object> metadata, CanonicalSecurityContext context) {
        ReasoningMemoryProfile existing = context.getReasoningMemoryProfile();
        ReasoningMemoryProfile profile = ReasoningMemoryProfile.builder()
                .summary(text(existing != null ? existing.getSummary() : null, metadata.get("reasoningMemorySummary"), metadata.get("reasoningSummary")))
                .reinforcedCaseCount(toLong(existing != null ? existing.getReinforcedCaseCount() : null, metadata.get("reinforcedCaseCount"), metadata.get("reinforcedCases")))
                .hardNegativeCaseCount(toLong(existing != null ? existing.getHardNegativeCaseCount() : null, metadata.get("hardNegativeCaseCount"), metadata.get("hardNegativeCases")))
                .falseNegativeCaseCount(toLong(existing != null ? existing.getFalseNegativeCaseCount() : null, metadata.get("falseNegativeCaseCount"), metadata.get("falseNegativeCases")))
                .knowledgeAssistedCaseCount(toLong(existing != null ? existing.getKnowledgeAssistedCaseCount() : null, metadata.get("knowledgeAssistedCaseCount"), metadata.get("knowledgeAssistedCases")))
                .objectiveAwareReasoningMemory(text(existing != null ? existing.getObjectiveAwareReasoningMemory() : null, metadata.get("objectiveAwareReasoningMemory"), metadata.get("objectiveAwareMemory")))
                .retentionTier(text(existing != null ? existing.getRetentionTier() : null, metadata.get("retentionTier"), metadata.get("reasoningRetentionTier")))
                .recallPriority(text(existing != null ? existing.getRecallPriority() : null, metadata.get("recallPriority"), metadata.get("reasoningRecallPriority")))
                .freshnessState(text(existing != null ? existing.getFreshnessState() : null, metadata.get("freshnessState"), metadata.get("reasoningFreshnessState")))
                .reasoningState(text(existing != null ? existing.getReasoningState() : null, metadata.get("reasoningState")))
                .cohortPreference(text(existing != null ? existing.getCohortPreference() : null, metadata.get("cohortPreference"), metadata.get("reasoningCohortPreference")))
                .memoryRiskProfile(text(existing != null ? existing.getMemoryRiskProfile() : null, metadata.get("memoryRiskProfile"), metadata.get("reasoningRiskProfile")))
                .retrievalWeight(toInt(existing != null ? existing.getRetrievalWeight() : null, metadata.get("retrievalWeight"), metadata.get("reasoningRetrievalWeight")))
                .matchedSignalKeys(strings(existing != null ? existing.getMatchedSignalKeys() : null, metadata.get("matchedSignalKeys"), metadata.get("threatKnowledgeSignalKeys"), metadata.get("threatKnowledgeKeys")))
                .objectiveFamilies(strings(existing != null ? existing.getObjectiveFamilies() : null, metadata.get("objectiveFamilies"), metadata.get("objective_families")))
                .memoryGuardrails(strings(existing != null ? existing.getMemoryGuardrails() : null, metadata.get("memoryGuardrails"), metadata.get("reasoningGuardrails"), metadata.get("reasoning_memory_guardrails")))
                .xaiLinkedFacts(strings(existing != null ? existing.getXaiLinkedFacts() : null, metadata.get("xaiLinkedFacts"), metadata.get("xaiFacts"), metadata.get("xai_linked_facts")))
                .reasoningFacts(strings(existing != null ? existing.getReasoningFacts() : null, metadata.get("reasoningFacts"), metadata.get("reasoning_facts")))
                .crossTenantObjectiveMisusePackSummary(text(existing != null ? existing.getCrossTenantObjectiveMisusePackSummary() : null, metadata.get("crossTenantObjectiveMisusePackSummary"), metadata.get("cross_tenant_objective_misuse_pack_summary")))
                .crossTenantObjectiveMisuseFacts(strings(existing != null ? existing.getCrossTenantObjectiveMisuseFacts() : null, metadata.get("crossTenantObjectiveMisuseFacts"), metadata.get("cross_tenant_objective_misuse_facts")))
                .build();

        if (!StringUtils.hasText(profile.getSummary())) {
            profile.setSummary(doBuildSummary(profile, context));
        }

        return profile;
    }

    @Override
    protected boolean doHasData(ReasoningMemoryProfile profile) {
        return StringUtils.hasText(profile.getSummary())
                || profile.getReinforcedCaseCount() != null
                || profile.getHardNegativeCaseCount() != null
                || profile.getFalseNegativeCaseCount() != null
                || profile.getKnowledgeAssistedCaseCount() != null
                || StringUtils.hasText(profile.getObjectiveAwareReasoningMemory())
                || StringUtils.hasText(profile.getRetentionTier())
                || StringUtils.hasText(profile.getRecallPriority())
                || StringUtils.hasText(profile.getFreshnessState())
                || StringUtils.hasText(profile.getReasoningState())
                || StringUtils.hasText(profile.getCohortPreference())
                || StringUtils.hasText(profile.getMemoryRiskProfile())
                || profile.getRetrievalWeight() != null
                || !profile.getMatchedSignalKeys().isEmpty()
                || !profile.getObjectiveFamilies().isEmpty()
                || !profile.getMemoryGuardrails().isEmpty()
                || !profile.getXaiLinkedFacts().isEmpty()
                || !profile.getReasoningFacts().isEmpty()
                || StringUtils.hasText(profile.getCrossTenantObjectiveMisusePackSummary())
                || !profile.getCrossTenantObjectiveMisuseFacts().isEmpty();
    }

    @Override
    protected String doBuildSummary(ReasoningMemoryProfile profile, CanonicalSecurityContext context) {
        List<String> facts = new ArrayList<>();
        if (profile.getReinforcedCaseCount() != null) {
            facts.add("Reinforced cases: " + profile.getReinforcedCaseCount());
        }
        if (profile.getHardNegativeCaseCount() != null) {
            facts.add("Hard negative cases: " + profile.getHardNegativeCaseCount());
        }
        if (profile.getFalseNegativeCaseCount() != null) {
            facts.add("False negative cases: " + profile.getFalseNegativeCaseCount());
        }
        if (profile.getKnowledgeAssistedCaseCount() != null) {
            facts.add("Knowledge-assisted cases: " + profile.getKnowledgeAssistedCaseCount());
        }
        if (StringUtils.hasText(profile.getObjectiveAwareReasoningMemory())) {
            facts.add("Objective-aware reasoning memory: " + profile.getObjectiveAwareReasoningMemory());
        }
        if (StringUtils.hasText(profile.getRetentionTier())) {
            facts.add("Retention tier: " + profile.getRetentionTier());
        }
        if (StringUtils.hasText(profile.getRecallPriority())) {
            facts.add("Recall priority: " + profile.getRecallPriority());
        }
        if (StringUtils.hasText(profile.getFreshnessState())) {
            facts.add("Freshness state: " + profile.getFreshnessState());
        }
        if (StringUtils.hasText(profile.getReasoningState())) {
            facts.add("Reasoning state: " + profile.getReasoningState());
        }
        if (StringUtils.hasText(profile.getCohortPreference())) {
            facts.add("Cohort preference: " + profile.getCohortPreference());
        }
        if (StringUtils.hasText(profile.getMemoryRiskProfile())) {
            facts.add("Memory risk profile: " + profile.getMemoryRiskProfile());
        }
        if (profile.getRetrievalWeight() != null) {
            facts.add("Retrieval weight: " + profile.getRetrievalWeight());
        }
        if (!profile.getMatchedSignalKeys().isEmpty()) {
            facts.add("Matched signal keys: " + String.join(", ", profile.getMatchedSignalKeys()));
        }
        if (!profile.getObjectiveFamilies().isEmpty()) {
            facts.add("Objective families: " + String.join(", ", profile.getObjectiveFamilies()));
        }
        if (!profile.getMemoryGuardrails().isEmpty()) {
            facts.add("Memory guardrails: " + String.join(", ", profile.getMemoryGuardrails()));
        }
        if (!profile.getReasoningFacts().isEmpty()) {
            facts.add("Reasoning facts: " + String.join(", ", profile.getReasoningFacts()));
        }
        if (StringUtils.hasText(profile.getCrossTenantObjectiveMisusePackSummary())) {
            facts.add("Cross-tenant objective misuse pack: " + profile.getCrossTenantObjectiveMisusePackSummary());
        }
        if (!profile.getCrossTenantObjectiveMisuseFacts().isEmpty()) {
            facts.add("Cross-tenant misuse facts: " + String.join(", ", profile.getCrossTenantObjectiveMisuseFacts()));
        }
        if (facts.isEmpty() && context != null && context.getDelegation() != null && StringUtils.hasText(context.getDelegation().getObjectiveFamily())) {
            facts.add("Reasoning memory is objective-aware for " + context.getDelegation().getObjectiveFamily());
        }
        return facts.isEmpty() ? null : String.join(" | ", facts);
    }

    @Override
    public void apply(ReasoningMemoryProfile profile, CanonicalSecurityContext context) {
        context.setReasoningMemoryProfile(profile);
    }
}
