package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityBehaviorProfileUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityPromptTemplate template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        template.appendIfPresent(section, template.buildObservedWorkPatternContextSection(context.getCanonicalSecurityContext()));
        template.appendIfPresent(section, template.buildPersonalWorkProfileContextSection(context.getCanonicalSecurityContext()));
        section.append(template.buildUserProfileNarrative(
                context.getEvent(),
                context.getDetectedPatterns(),
                context.getBehaviorAnalysis(),
                context.getBaselineStatus()
        ));
        section.append(template.buildNetworkPromptSection(context.getEvent()));
        template.appendIfPresent(section, template.buildPayloadSection(context.getEvent()));
        return section.toString();
    }
}
