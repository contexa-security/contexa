package io.contexa.contexacore.autonomous.tiered.prompt;

public class SecuritySupportingLearningUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        return template.buildSupportingLearningContextSection(context.getBehaviorAnalysis());
    }
}
