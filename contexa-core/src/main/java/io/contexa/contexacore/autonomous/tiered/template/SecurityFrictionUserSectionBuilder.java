package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityFrictionUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityPromptTemplate template, SecurityPromptBuildContext context) {
        return template.buildFrictionAndApprovalHistorySection(context.getCanonicalSecurityContext());
    }
}
