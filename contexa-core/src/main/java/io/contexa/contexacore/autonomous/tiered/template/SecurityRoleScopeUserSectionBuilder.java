package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityRoleScopeUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityPromptTemplate template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        template.appendIfPresent(section, template.buildRoleAndWorkScopeContextSection(context.getCanonicalSecurityContext()));
        template.appendIfPresent(section, template.buildPeerCohortDeltaSection(context.getCanonicalSecurityContext()));
        return section.toString();
    }
}
