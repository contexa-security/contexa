package io.contexa.contexacore.autonomous.tiered.template;

public interface SecurityPromptSectionBuilder {

    String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context);
}
