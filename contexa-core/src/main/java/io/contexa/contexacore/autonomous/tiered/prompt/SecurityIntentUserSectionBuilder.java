package io.contexa.contexacore.autonomous.tiered.prompt;

public class SecurityIntentUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        return template.buildIntentSignalContextSection(context.getCanonicalSecurityContext());
    }
}
