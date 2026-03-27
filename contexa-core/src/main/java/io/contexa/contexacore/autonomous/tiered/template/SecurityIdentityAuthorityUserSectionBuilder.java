package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityIdentityAuthorityUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        template.appendIfPresent(section, template.buildIdentityAndRoleContextSection(context.getCanonicalSecurityContext()));
        template.appendIfPresent(section, template.buildAuthenticationAndAssuranceContextSection(context.getCanonicalSecurityContext()));
        return section.toString();
    }
}
