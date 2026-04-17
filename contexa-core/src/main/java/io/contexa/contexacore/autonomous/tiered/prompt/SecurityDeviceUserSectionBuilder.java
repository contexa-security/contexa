package io.contexa.contexacore.autonomous.tiered.prompt;

public class SecurityDeviceUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        return template.buildDeviceContextSection(context.getCanonicalSecurityContext());
    }
}
