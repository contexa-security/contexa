package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityResourceSemanticsUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityPromptTemplate template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        template.appendIfPresent(section, template.buildResourceAndActionContextSection(context.getCanonicalSecurityContext()));
        template.appendIfPresent(section, template.buildMcpSecurityContextSection(context.getEvent()));
        return section.toString();
    }
}
