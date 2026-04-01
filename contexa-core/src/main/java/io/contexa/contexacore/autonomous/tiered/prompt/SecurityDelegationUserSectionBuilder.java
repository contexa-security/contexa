package io.contexa.contexacore.autonomous.tiered.prompt;

public class SecurityDelegationUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        return template.buildDelegatedObjectiveContextSection(context.getCanonicalSecurityContext());
    }
}
