package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityBehaviorProfileUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        String observedWorkPatternSection = template.buildObservedWorkPatternContextSection(context.getCanonicalSecurityContext());
        String personalWorkProfileSection = template.buildPersonalWorkProfileContextSection(context.getCanonicalSecurityContext());
        String historicalBaselineSupport = template.buildSupportingPromptBlock(
                "HistoricalBaselineSupport",
                template.buildUserProfileNarrative(
                        context.getEvent(),
                        context.getDetectedPatterns(),
                        context.getBehaviorAnalysis(),
                        context.getBaselineStatus()
                )
        );

        template.appendIfPresent(section, observedWorkPatternSection);
        if (personalWorkProfileSection == null && historicalBaselineSupport != null) {
            section.append("\n=== PERSONAL WORK PROFILE ===\n");
        }
        template.appendIfPresent(section, personalWorkProfileSection);
        template.appendIfPresent(section, historicalBaselineSupport);
        return section.toString();
    }
}
