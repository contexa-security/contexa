package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityInstructionSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityPromptTemplate template, SecurityPromptBuildContext context) {
        return template.buildSystemInstruction();
    }
}
