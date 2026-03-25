package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityThreatLearningUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityPromptTemplate template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        template.appendIfPresent(section, template.buildReasoningMemoryContextSection(context.getCanonicalSecurityContext()));
        template.appendIfPresent(section, template.buildThreatLearningSection(context.getBehaviorAnalysis()));
        template.appendIfPresent(section, template.buildCohortBaselineSeedSection(context.getBehaviorAnalysis()));
        template.appendIfPresent(section, template.buildNewUserBaselineSection(
                context.getBaselineStatus(),
                context.getBaselineContext()
        ));
        return section.toString();
    }
}
