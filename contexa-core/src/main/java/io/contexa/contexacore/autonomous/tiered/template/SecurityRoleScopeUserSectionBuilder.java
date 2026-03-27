package io.contexa.contexacore.autonomous.tiered.template;

public class SecurityRoleScopeUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        String roleScopeSection = template.buildRoleAndWorkScopeContextSection(context.getCanonicalSecurityContext());
        String peerCohortSection = template.buildPeerCohortDeltaSection(context.getCanonicalSecurityContext());
        String cohortSeedSupport = template.buildSupportingPromptBlock(
                "CohortSeedSupport",
                template.buildCohortBaselineSeedSection(context.getBehaviorAnalysis())
        );

        template.appendIfPresent(section, roleScopeSection);
        if (peerCohortSection == null && cohortSeedSupport != null) {
            section.append("\n=== PEER COHORT DELTA ===\n");
        }
        template.appendIfPresent(section, peerCohortSection);
        template.appendIfPresent(section, cohortSeedSupport);
        return section.toString();
    }
}
