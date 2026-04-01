package io.contexa.contexacore.autonomous.tiered.prompt;

public class SecurityInstructionSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        return template.buildSystemInstruction();
    }
}
