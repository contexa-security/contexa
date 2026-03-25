package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityDelegationUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityPromptTemplate template, SecurityPromptBuildContext context) {
        return template.buildDelegatedObjectiveContextSection(context.getCanonicalSecurityContext());
    }
}
