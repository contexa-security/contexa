package io.contexa.demo.platform.context;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.enricher.FrictionContextProvider;
import io.contexa.demo.work.approval.dto.ApprovalEvidence;
import io.contexa.demo.work.request.dto.WorkRequestSnapshot;
import io.contexa.demo.work.request.repository.BusinessRequestRepository;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Component
@Profile("contexa")
public class BusinessFrictionContextProvider extends AbstractBusinessContextProvider implements FrictionContextProvider {

    public BusinessFrictionContextProvider(BusinessRequestRepository requests) {
        super(requests);
    }

    @Override
    protected void contribute(WorkRequestSnapshot snapshot, CanonicalSecurityContext context) {
        ApprovalEvidence evidence = snapshot.approval();
        if (evidence == null) {
            return;
        }
        FrictionProfile profile = context.getFrictionProfile();
        if (profile == null) {
            profile = new FrictionProfile();
            context.setFrictionProfile(profile);
        }
        profile.setApprovalRequired(evidence.required());
        profile.setApprovalGranted(evidence.usable());
        profile.setApprovalMissing(evidence.required() && !evidence.usable());
        profile.setApprovalStatus(evidence.status());
        profile.setApprovalTicketId(evidence.approvalId() == null ? null : evidence.approvalId().toString());
        profile.setApprovalDecisionAgeMinutes(evidence.decidedAt() == null ? null :
                (int) Math.min(Integer.MAX_VALUE, Math.max(0, Duration.between(evidence.decidedAt(), evidence.observedAt()).toMinutes())));
        List<String> lineage = new ArrayList<>();
        lineage.add("Business approval evidence at request time; source=" + evidence.source());
        lineage.add("Applies only to this request; not authentication, MFA completion, or security action release.");
        if (evidence.usable()) {
            lineage.add("Decision=" + evidence.decisionId() + "; reviewer=" + evidence.reviewer()
                    + "; purpose=" + evidence.purpose() + "; expiresAt=" + evidence.expiresAt());
            lineage.add("Matched resource=" + snapshot.resourceFacts().id() + "; version="
                    + snapshot.resourceFacts().version() + "; requester=" + evidence.requester());
        }
        profile.setApprovalLineage(lineage);
    }
}
