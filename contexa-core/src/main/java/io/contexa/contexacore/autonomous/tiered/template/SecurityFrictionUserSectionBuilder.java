package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityFrictionUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        return template.buildFrictionAndApprovalHistorySection(context.getCanonicalSecurityContext());
    }
}
