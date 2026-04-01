package io.contexa.contexacore.autonomous.tiered.prompt;

public interface SecurityPromptSectionBuilder {

    String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context);
}
