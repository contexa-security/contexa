package io.contexa.contexacore.autonomous.tiered.prompt;

public class SecurityEventUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        return template.buildCurrentRequestAndEventSection(
                context.getEvent(),
                context.getUserId(),
                context.getBehaviorAnalysis(),
                context.getCanonicalSecurityContext(),
                context.getDetectedPatterns()
        );
    }
}
