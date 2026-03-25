package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityCanonicalContextUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityPromptTemplate template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        template.appendIfPresent(section, template.buildBridgeResolutionSection(context.getCanonicalSecurityContext()));
        template.appendIfPresent(section, template.buildCoverageSection(context.getCanonicalSecurityContext()));
        return section.toString();
    }
}
