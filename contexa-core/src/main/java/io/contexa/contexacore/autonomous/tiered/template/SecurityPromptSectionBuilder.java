package io.contexa.contexacore.autonomous.tiered.template;

public interface SecurityPromptSectionBuilder {

    String build(SecurityPromptTemplate template, SecurityPromptBuildContext context);
}
