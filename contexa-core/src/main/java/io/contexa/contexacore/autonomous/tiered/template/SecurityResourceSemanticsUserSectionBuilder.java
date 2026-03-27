package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityResourceSemanticsUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        String resourceSection = template.buildResourceAndActionContextSection(context.getCanonicalSecurityContext());
        String mcpSupport = template.buildSupportingPromptBlock(
                "McpSecurityContext",
                template.buildMcpSecurityContextSection(context.getEvent())
        );

        if (resourceSection == null && mcpSupport != null) {
            section.append("\n=== RESOURCE AND ACTION CONTEXT ===\n");
        }

        template.appendIfPresent(section, resourceSection);
        template.appendIfPresent(section, mcpSupport);
        return section.toString();
    }
}
