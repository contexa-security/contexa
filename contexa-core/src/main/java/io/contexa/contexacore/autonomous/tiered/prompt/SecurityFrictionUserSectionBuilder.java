package io.contexa.contexacore.autonomous.tiered.prompt;

public class SecurityFrictionUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        return template.buildFrictionAndApprovalHistorySection(context.getCanonicalSecurityContext());
    }
}
