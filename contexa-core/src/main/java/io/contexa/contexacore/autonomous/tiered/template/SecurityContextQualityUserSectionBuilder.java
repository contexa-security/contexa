package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityContextQualityUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        String missingKnowledgeSection = template.buildExplicitMissingKnowledgeSection(context.getCanonicalSecurityContext());
        String baselineGapSupport = template.buildSupportingPromptBlock(
                "BaselineGapSupport",
                template.buildNewUserBaselineSection(
                        context.getBaselineStatus(),
                        context.getBaselineContext()
                )
        );

        if (missingKnowledgeSection == null && baselineGapSupport != null) {
            section.append("\n=== EXPLICIT MISSING KNOWLEDGE ===\n");
        }

        template.appendIfPresent(section, missingKnowledgeSection);
        template.appendIfPresent(section, baselineGapSupport);
        return section.toString();
    }
}
