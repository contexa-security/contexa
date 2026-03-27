package io.contexa.contexacore.autonomous.tiered.template;

public class SecuritySessionUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        String sessionNarrativeSection = template.buildSessionNarrativeContextSection(context.getCanonicalSecurityContext());
        String sessionTimelineSupport = template.buildSupportingPromptBlock(
                "SessionTimelineSupport",
                template.buildSessionTimelineSection(
                        context.getSessionContext(),
                        context.getBehaviorAnalysis()
                )
        );
        String sessionDeviceChangeSupport = template.buildSupportingPromptBlock(
                "SessionDeviceChangeSupport",
                template.buildSessionDeviceChangeSection(context.getBehaviorAnalysis())
        );
        String historicalComparableSupport = null;
        boolean hasHistoricalComparables =
                (context.getBehaviorAnalysis() != null && !context.getBehaviorAnalysis().getSimilarEvents().isEmpty())
                        || (context.getDetectedPatterns() != null && context.getDetectedPatterns().hasRelatedDocs);
        if (hasHistoricalComparables) {
            historicalComparableSupport = template.buildSupportingPromptBlock(
                    "HistoricalComparableEvents",
                    template.buildSimilarEventsSection(
                            context.getBehaviorAnalysis(),
                            context.getDetectedPatterns()
                    )
            );
        }

        if (sessionNarrativeSection == null
                && (sessionTimelineSupport != null
                || sessionDeviceChangeSupport != null
                || historicalComparableSupport != null)) {
            section.append("\n=== SESSION NARRATIVE CONTEXT ===\n");
        }

        template.appendIfPresent(section, sessionNarrativeSection);
        template.appendIfPresent(section, sessionTimelineSupport);
        template.appendIfPresent(section, sessionDeviceChangeSupport);
        template.appendIfPresent(section, historicalComparableSupport);
        return section.toString();
    }
}
