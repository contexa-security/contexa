package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityEventUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        return template.buildCurrentRequestAndEventSection(
                context.getEvent(),
                context.getUserId(),
                context.getBehaviorAnalysis(),
                context.getDetectedPatterns()
        );
    }
}
