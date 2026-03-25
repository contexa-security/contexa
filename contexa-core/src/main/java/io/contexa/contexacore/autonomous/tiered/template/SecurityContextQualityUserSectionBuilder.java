package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityContextQualityUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityPromptTemplate template, SecurityPromptBuildContext context) {
        return template.buildExplicitMissingKnowledgeSection(context.getCanonicalSecurityContext());
    }
}
