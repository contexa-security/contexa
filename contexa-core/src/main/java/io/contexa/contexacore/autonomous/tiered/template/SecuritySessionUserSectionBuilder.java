package io.contexa.contexacore.autonomous.tiered.template;

public class SecuritySessionUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityPromptTemplate template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        template.appendIfPresent(section, template.buildSessionNarrativeContextSection(context.getCanonicalSecurityContext()));
        section.append(template.buildSessionTimelineSection(
                context.getSessionContext(),
                context.getBehaviorAnalysis()
        ));
        template.appendIfPresent(section, template.buildSessionDeviceChangeSection(context.getBehaviorAnalysis()));
        section.append(template.buildSimilarEventsSection(
                context.getBehaviorAnalysis(),
                context.getDetectedPatterns()
        ));
        return section.toString();
    }
}
