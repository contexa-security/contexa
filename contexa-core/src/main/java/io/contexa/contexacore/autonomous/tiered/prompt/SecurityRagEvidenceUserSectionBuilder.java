package io.contexa.contexacore.autonomous.tiered.prompt;

public class SecurityRagEvidenceUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        return template.buildRagEvidenceContextSection(context);
    }
}
