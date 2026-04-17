package io.contexa.contexacore.autonomous.tiered.prompt;

public class SecurityLocationUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        return template.buildLocationContextSection(context.getCanonicalSecurityContext());
    }
}
