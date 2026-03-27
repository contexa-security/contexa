package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityThreatLearningUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        String reasoningMemorySection = template.buildReasoningMemoryContextSection(context.getCanonicalSecurityContext());
        String threatKnowledgeSupport = template.buildSupportingPromptBlock(
                "ThreatKnowledgeSupport",
                template.buildThreatLearningSection(context.getBehaviorAnalysis())
        );

        if (reasoningMemorySection == null && threatKnowledgeSupport != null) {
            section.append("\n=== OUTCOME AND REASONING MEMORY ===\n");
        }
        template.appendIfPresent(section, reasoningMemorySection);
        template.appendIfPresent(section, threatKnowledgeSupport);
        return section.toString();
    }
}
