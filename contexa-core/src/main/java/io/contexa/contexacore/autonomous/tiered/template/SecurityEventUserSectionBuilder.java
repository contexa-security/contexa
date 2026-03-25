package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityEventUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityPromptTemplate template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        section.append(template.buildEventSection(context.getEvent(), context.getUserId()));
        section.append(template.buildCurrentRequestNarrative(
                context.getEvent(),
                context.getBehaviorAnalysis(),
                context.getDetectedPatterns()
        ));
        return section.toString();
    }
}
