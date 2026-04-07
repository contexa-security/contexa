package io.contexa.contexacore.autonomous.context.resolver;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.PeerCohortProfile;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;

/**
 * Resolves PeerCohortProfile from metadata.
 * Extracted from DefaultCanonicalSecurityContextProvider - all business logic preserved.
 */
public class PeerCohortProfileResolver extends AbstractProfileResolver<PeerCohortProfile> {

    @Override
    protected PeerCohortProfile doResolve(Map<String, Object> metadata, CanonicalSecurityContext context) {
        PeerCohortProfile existing = context.getPeerCohortProfile();
        PeerCohortProfile profile = PeerCohortProfile.builder()
                .cohortId(text(existing != null ? existing.getCohortId() : null, metadata.get("peerCohortId"), metadata.get("cohortId"), metadata.get("peer_cohort_id")))
                .summary(text(existing != null ? existing.getSummary() : null, metadata.get("peerCohortSummary"), metadata.get("cohortDeltaSummary"), metadata.get("cohortSummary")))
                .preferredResources(strings(
                        existing != null ? existing.getPreferredResources() : null,
                        metadata.get("cohortPreferredResources"),
                        metadata.get("peerPreferredResources"),
                        metadata.get("peerCohortPreferredResources")))
                .preferredActionFamilies(strings(
                        existing != null ? existing.getPreferredActionFamilies() : null,
                        metadata.get("cohortPreferredActionFamilies"),
                        metadata.get("peerPreferredActionFamilies"),
                        metadata.get("peerCohortPreferredActionFamilies")))
                .normalProtectableFrequencyBand(text(
                        existing != null ? existing.getNormalProtectableFrequencyBand() : null,
                        metadata.get("cohortNormalProtectableFrequencyBand"),
                        metadata.get("peerNormalProtectableFrequencyBand")))
                .normalSensitivityBand(text(
                        existing != null ? existing.getNormalSensitivityBand() : null,
                        metadata.get("cohortNormalSensitivityBand"),
                        metadata.get("peerNormalSensitivityBand")))
                .outlierAgainstCohort(toBool(
                        existing != null ? existing.getOutlierAgainstCohort() : null,
                        metadata.get("outlierAgainstCohort"),
                        metadata.get("cohortOutlier"),
                        metadata.get("peerOutlier")))
                .build();

        if (!StringUtils.hasText(profile.getSummary())) {
            profile.setSummary(doBuildSummary(profile, context));
        }

        return profile;
    }

    @Override
    protected boolean doHasData(PeerCohortProfile profile) {
        return StringUtils.hasText(profile.getCohortId())
                || StringUtils.hasText(profile.getSummary())
                || !profile.getPreferredResources().isEmpty()
                || !profile.getPreferredActionFamilies().isEmpty()
                || StringUtils.hasText(profile.getNormalProtectableFrequencyBand())
                || StringUtils.hasText(profile.getNormalSensitivityBand())
                || profile.getOutlierAgainstCohort() != null;
    }

    @Override
    protected String doBuildSummary(PeerCohortProfile profile, CanonicalSecurityContext context) {
        List<String> facts = new ArrayList<>();
        if (StringUtils.hasText(profile.getCohortId())) {
            facts.add("Peer cohort id: " + profile.getCohortId());
        }
        if (!profile.getPreferredResources().isEmpty()) {
            facts.add("Cohort preferred resources: " + String.join(", ", profile.getPreferredResources()));
        }
        if (!profile.getPreferredActionFamilies().isEmpty()) {
            facts.add("Cohort preferred action families: " + String.join(", ", profile.getPreferredActionFamilies()));
        }
        if (StringUtils.hasText(profile.getNormalProtectableFrequencyBand())) {
            facts.add("Cohort normal protectable frequency band: " + profile.getNormalProtectableFrequencyBand());
        }
        if (StringUtils.hasText(profile.getNormalSensitivityBand())) {
            facts.add("Cohort normal sensitivity band: " + profile.getNormalSensitivityBand());
        }
        if (facts.isEmpty() && context != null && context.getActor() != null && StringUtils.hasText(context.getActor().getDepartment())) {
            facts.add("Peer cohort reasoning is anchored to department " + context.getActor().getDepartment());
        }
        return facts.isEmpty() ? null : String.join(" | ", facts);
    }

    @Override
    public void apply(PeerCohortProfile profile, CanonicalSecurityContext context) {
        context.setPeerCohortProfile(profile);
    }
}
