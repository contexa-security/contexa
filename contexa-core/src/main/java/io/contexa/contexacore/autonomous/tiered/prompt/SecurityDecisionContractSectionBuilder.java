package io.contexa.contexacore.autonomous.tiered.prompt;

public class SecurityDecisionContractSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        return template.buildDecisionSection();
    }
}
