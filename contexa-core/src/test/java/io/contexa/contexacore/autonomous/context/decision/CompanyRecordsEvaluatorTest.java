/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.context.decision;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.ApprovalRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.CompanyPolicy;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.PolicyException;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.TicketRecord;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** W2-5: the company records of a request are checked at the time of the request. */
class CompanyRecordsEvaluatorTest {

    private static final ZoneId UTC = ZoneOffset.UTC;
    private static final Instant AT = Instant.parse("2026-09-30T14:20:00Z");
    private static final String TARGET = "projectKey=GB-500";

    @Test
    void anApprovalDecidedAfterTheRequestDoesNotCoverIt() {
        // Case S12: the approval's decision was recorded 20 minutes after the request; the host still said it covers.
        ApprovalRecord approval = approval("APR-1", 500).decidedAt(AT.plus(Duration.ofMinutes(20)))
                .validFrom(AT.minus(Duration.ofHours(2))).hostCovers(true).build();

        CompanyRecordsEvaluator.Evaluation evaluation = evaluate(profile(List.of(approval), List.of(), exportPolicy()),
                request(300, List.of()));

        assertThat(evaluation.approvals().get(0).valid()).isFalse();
        assertThat(evaluation.approvals().get(0).failures()).containsExactly(PolicyReason.LATE);
        assertThat(evaluation.covering()).isEmpty();
        assertThat(evaluation.policy().satisfied()).isFalse();
        assertThat(evaluation.policy().reason()).isEqualTo(PolicyReason.LATE);
        assertThat(evaluation.policy().describe()).isEqualTo("no — approval APR-1 decided 20 min after this request");
        assertThat(evaluation.policy().reason().code()).isEqualTo("POLICY_NOT_SATISFIED_LATE");
    }

    @Test
    void whatTheSessionAlreadyExportedUnderAnApprovalCountsAgainstItsLimit() {
        // Case S11: 480 items five times a minute apart under an approval of 500.
        ApprovalRecord approval = approval("APR-1", 500).purpose("AUDIT_SAMPLE").build();
        FrictionProfile profile = profile(List.of(approval), List.of(), exportPolicy());

        // The first export fits the limit, but what was exported under the approval outside this session is not
        // reported: the policy is not known to be satisfied (P2 correction 3).
        CompanyRecordsEvaluator.Evaluation first = evaluate(profile, request(480, List.of()));
        assertThat(first.approvals().get(0).undecided()).isTrue();
        assertThat(first.covering()).isEmpty();
        assertThat(first.policy().satisfied()).isNull();
        assertThat(first.policy().describe()).isEqualTo("unknown — not known: approval APR-1: the items exported under "
                + "it outside this session (the host does not report them)");

        List<SessionDecisionRecord> session = List.of(
                exported(AT.minusSeconds(60), TARGET, 480, "ALLOW"),
                // A challenged export did not leave, and another project is another approval's business.
                exported(AT.minusSeconds(50), TARGET, 480, "CHALLENGE"),
                exported(AT.minusSeconds(40), "projectKey=HX-200", 480, "ALLOW"));
        CompanyRecordsEvaluator.Evaluation second = evaluate(profile, request(480, session));

        assertThat(second.approvals().get(0).failures()).containsExactly(PolicyReason.CUMULATIVE);
        assertThat(second.approvals().get(0).usedBefore()).isEqualTo(480);
        assertThat(second.policy().describe()).isEqualTo(
                "no — approval APR-1 cumulative 960 of 500 items with 480 already exported in this session");

        // The host's own count of what was used before, when it has one, is the count.
        ApprovalRecord counted = approval("APR-1", 500).usedItems(0).build();
        assertThat(evaluate(profile(List.of(counted), List.of(), exportPolicy()), request(480, session))
                .policy().satisfied()).isTrue();
        ApprovalRecord used = approval("APR-1", 500).usedItems(480).build();
        assertThat(evaluate(profile(List.of(used), List.of(), exportPolicy()), request(480, List.of())).policy()
                .describe()).isEqualTo("no — approval APR-1 cumulative 960 of 500 items with 480 already exported under it");
    }

    @Test
    void anApprovalWithALimitDoesNotCoverARequestThatDoesNotStateItsItemCount() {
        ApprovalRecord approval = approval("APR-1", 500).usedItems(0).build();

        CompanyRecordsEvaluator.Evaluation evaluation = evaluate(profile(List.of(approval), List.of(), exportPolicy()),
                request(null, List.of()));

        assertThat(evaluation.approvals().get(0).unknowns())
                .containsExactly("the request's item count against its limit of 500 (the request does not state it)");
        assertThat(evaluation.policy().satisfied()).isNull();
        assertThat(evaluation.covering()).isEmpty();
    }

    @Test
    void onlyARecordThatSatisfiesThePoliciesCoversTheWork() {
        // A valid ticket where an approval is required, and the requester not on call: the ticket covers nothing,
        // so it cannot explain a difference or be reported as the granted approval (P2 correction 3).
        TicketRecord ticket = TicketRecord.builder().ticketId("TCK-1").target("GB-500")
                .validFrom(AT.minus(Duration.ofHours(1))).validUntil(AT.plus(Duration.ofHours(5))).hostCovers(true)
                .build();
        FrictionProfile notOnCall = profile(List.of(), List.of(ticket), exportPolicy());
        notOnCall.setOnCall(CanonicalSecurityContext.OnCallRecord.builder().onCall(false).build());

        CompanyRecordsEvaluator.Evaluation evaluation = evaluate(notOnCall, request(300, List.of()));

        assertThat(evaluation.tickets().get(0).valid()).isTrue();
        assertThat(evaluation.policy().reason()).isEqualTo(PolicyReason.TICKET_WITHOUT_ON_CALL);
        assertThat(evaluation.covering()).isEmpty();
        // Without stated policies a valid record still covers its own work.
        FrictionProfile noPolicy = profile(List.of(), List.of(ticket));
        assertThat(evaluate(noPolicy, request(300, List.of())).covering()).get()
                .extracting(RecordCheck::recordId).isEqualTo("TCK-1");
    }

    @Test
    void aFactTheHostDidNotLookUpLeavesThePolicyNotKnown() {
        TicketRecord ticket = TicketRecord.builder().ticketId("TCK-1").target("GB-500")
                .validFrom(AT.minus(Duration.ofHours(1))).validUntil(AT.plus(Duration.ofHours(5))).hostCovers(true)
                .build();
        // A ticket covers the work, but whether the requester is on call is not reported.
        FrictionProfile onCallUnknown = profile(List.of(), List.of(ticket), exportPolicy());
        onCallUnknown.setCheckedRecordKinds(new ArrayList<>(List.of("APPROVAL", "TICKET", "ASSIGNMENT")));
        onCallUnknown.setAssignment(CanonicalSecurityContext.AssignmentRecord.builder().target("GB-500")
                .assigned(false).build());
        assertThat(evaluate(onCallUnknown, request(300, List.of())).policy().describe())
                .isEqualTo("unknown — not known: ticket TCK-1 covers GB-500, but whether the requester is on call is not reported");

        // A host that states no lookups: no approval found is not the same as none looked up.
        FrictionProfile nothingLookedUp = FrictionProfile.builder()
                .policies(new ArrayList<>(List.of(exportPolicy()))).build();
        assertThat(evaluate(nothingLookedUp, request(300, List.of())).policy().describe())
                .isEqualTo("unknown — not known: approvals were not looked up; the assignment to this target was not "
                        + "looked up; tickets were not looked up");
        nothingLookedUp.setCheckedRecordKinds(new ArrayList<>(List.of("APPROVAL", "TICKET", "ASSIGNMENT")));
        assertThat(evaluate(nothingLookedUp, request(300, List.of())).policy().describe())
                .isEqualTo("no — no approval for this target");
    }

    @Test
    void aRequestBeyondTheLimitOrOutsideTheValidityOrForAnotherTargetIsNotCovered() {
        assertThat(evaluate(profile(List.of(approval("APR-1", 500).build()), List.of(), exportPolicy()),
                request(600, List.of())).approvals().get(0).failures()).containsExactly(PolicyReason.OVER_LIMIT);

        ApprovalRecord expired = approval("APR-2", 500).validFrom(AT.minus(Duration.ofDays(3)))
                .validUntil(AT.minus(Duration.ofDays(1))).build();
        RecordCheck check = evaluate(profile(List.of(expired), List.of(), exportPolicy()), request(10, List.of()))
                .approvals().get(0);
        assertThat(check.failures()).containsExactly(PolicyReason.EXPIRED);
        assertThat(check.notes()).containsExactly("valid 09-27 14:20..09-29 14:20 (from 3 days before to 24 h before this request), the request is outside it");

        ApprovalRecord otherTarget = approval("APR-3", 500).hostMismatches(new ArrayList<>(List.of("TARGET")))
                .target(null).build();
        assertThat(evaluate(profile(List.of(otherTarget), List.of(), exportPolicy()), request(10, List.of()))
                .policy().reason()).isEqualTo(PolicyReason.OTHER_TARGET);
    }

    @Test
    void anApprovalThatIsNotApprovedCoversNothingAndKeepsItsState() {
        ApprovalRecord pending = approval("SOAR-7", null).status("PENDING").pendingApprovers(new ArrayList<>(
                List.of("security-lead"))).build();

        CompanyRecordsEvaluator.Evaluation evaluation = evaluate(profile(List.of(pending), List.of()),
                request(null, List.of()));

        assertThat(evaluation.approvals().get(0).failures()).containsExactly(PolicyReason.NO_RECORD);
        assertThat(evaluation.approvals().get(0).notes()).containsExactly("is PENDING");
        // Without a stated policy there is nothing to be satisfied or not.
        assertThat(evaluation.policy()).isEqualTo(PolicySatisfaction.UNKNOWN);
    }

    @Test
    void aTicketTheRequesterNamedThatDoesNotExistCoversNothing() {
        // Case A8: the requester names INC-7781, which does not exist.
        TicketRecord claimed = TicketRecord.builder().ticketId("INC-7781").claimedByRequester(true).exists(false)
                .hostCovers(false).build();

        CompanyRecordsEvaluator.Evaluation evaluation = evaluate(profile(List.of(), List.of(claimed), exportPolicy()),
                request(300, List.of()));

        assertThat(evaluation.tickets().get(0).claimFalse()).isTrue();
        assertThat(evaluation.policy().reason()).isEqualTo(PolicyReason.NO_RECORD);
        // N-INJ-1: without a host record target, the request path's value is the requester's text.
        assertThat(evaluation.policy().detail()).isEqualTo("no approval for this target");
    }

    @Test
    void aTicketExemptsAnExportOnlyWhileTheRequesterIsOnCall() {
        // Cases A8T and S03: a ticket that covers the project and the on-call roster make the exception.
        TicketRecord ticket = TicketRecord.builder().ticketId("TCK-1").target("GB-500")
                .validFrom(AT.minus(Duration.ofHours(1))).validUntil(AT.plus(Duration.ofHours(5))).hostCovers(true)
                .build();
        FrictionProfile onCall = profile(List.of(), List.of(ticket), exportPolicy());
        onCall.setOnCall(CanonicalSecurityContext.OnCallRecord.builder().onCall(true).team("PLATFORM")
                .startsAt(AT.minus(Duration.ofHours(2))).endsAt(AT.plus(Duration.ofHours(6))).build());

        CompanyRecordsEvaluator.Evaluation covered = evaluate(onCall, request(300, List.of()));
        assertThat(covered.policy().describe())
                .isEqualTo("yes — ticket TCK-1 covers GB-500 and the requester is on call");
        assertThat(covered.policy().recordIds()).containsExactly("TCK-1");
        assertThat(covered.covering()).get().extracting(RecordCheck::recordId).isEqualTo("TCK-1");

        FrictionProfile offCall = profile(List.of(), List.of(ticket), exportPolicy());
        offCall.setOnCall(CanonicalSecurityContext.OnCallRecord.builder().onCall(true)
                .startsAt(AT.plus(Duration.ofHours(1))).endsAt(AT.plus(Duration.ofHours(9))).build());
        CompanyRecordsEvaluator.Evaluation notOnCall = evaluate(offCall, request(300, List.of()));
        assertThat(notOnCall.onCall()).isFalse();
        assertThat(notOnCall.policy().reason()).isEqualTo(PolicyReason.TICKET_WITHOUT_ON_CALL);
        assertThat(notOnCall.policy().detail()).isEqualTo("ticket TCK-1 covers GB-500, but the requester is not on call");
    }

    @Test
    void anExpiredTicketLeavesAnAccessPolicyUnsatisfied() {
        // Case S07: the closest ticket ended two hours before the request.
        TicketRecord ticket = TicketRecord.builder().ticketId("TCK-1").target("HX-450")
                .validFrom(AT.minus(Duration.ofHours(6))).validUntil(AT.minus(Duration.ofHours(2)))
                .hostCovers(false).hostMismatches(new ArrayList<>(List.of("VALIDITY"))).build();
        FrictionProfile profile = profile(List.of(), List.of(ticket), documentPolicy());
        profile.setAssignment(CanonicalSecurityContext.AssignmentRecord.builder().target("HX-450").assigned(false)
                .build());
        profile.setAccessHistory(CanonicalSecurityContext.AccessHistoryRecord.builder().target("HX-450").days(0)
                .windowDays(90).build());

        CompanyRecordsEvaluator.Evaluation evaluation = evaluate(profile, request(null, List.of()));

        assertThat(evaluation.policy().reason()).isEqualTo(PolicyReason.EXPIRED);
        assertThat(evaluation.policy().describe())
                .isEqualTo("no — ticket TCK-1 valid 09-30 08:20..09-30 12:20 (from 6 h before to 2 h before this request), "
                        + "the request is outside it");
    }

    @Test
    void thePolicyExceptionsAreTheHostsAssignmentAccountAndRecentWorkFacts() {
        FrictionProfile assigned = profile(List.of(), List.of(), exportPolicy());
        assigned.setAssignment(CanonicalSecurityContext.AssignmentRecord.builder().target("HX-310").assigned(true)
                .responsibility("DESIGN").build());
        assertThat(evaluate(assigned, request(480, List.of())).policy().describe())
                .isEqualTo("yes — assigned to HX-310, 480 items within the assigned limit of 500");
        assertThat(evaluate(assigned, request(600, List.of())).policy().describe())
                .isEqualTo("no — no approval for HX-310");

        FrictionProfile manager = profile(List.of(), List.of(), customerPolicy());
        manager.setAssignment(CanonicalSecurityContext.AssignmentRecord.builder().target("CUS-0001").assigned(true)
                .responsibility("ACCOUNT_MANAGER").build());
        assertThat(evaluate(manager, request(null, List.of())).policy().describe())
                .isEqualTo("yes — account manager of CUS-0001");
        // Being the account manager of a customer is not an assignment to a project.
        FrictionProfile managerOnDocuments = profile(List.of(), List.of(), documentPolicy());
        managerOnDocuments.setAssignment(manager.getAssignment());
        assertThat(evaluate(managerOnDocuments, request(null, List.of())).policy().satisfied()).isFalse();

        FrictionProfile recent = profile(List.of(), List.of(), documentPolicy());
        recent.setAccessHistory(CanonicalSecurityContext.AccessHistoryRecord.builder().target("HX-310").days(59)
                .windowDays(90).build());
        assertThat(evaluate(recent, request(null, List.of())).policy().describe())
                .isEqualTo("yes — worked on HX-310 on 59 of the last 90 days");
    }

    @Test
    void aRoleGrantNeedsAChangeTicket() {
        TicketRecord incident = TicketRecord.builder().ticketId("TCK-1").kind("INCIDENT").target("GB-500")
                .hostCovers(true).build();
        CompanyPolicy grant = CompanyPolicy.builder().policyId("ROLE_GRANT_APPROVAL").requirement("TICKET")
                .requiredTicketKind("CHANGE").build();

        CompanyRecordsEvaluator.Evaluation evaluation = evaluate(profile(List.of(), List.of(incident), grant),
                request(null, List.of()));

        assertThat(evaluation.policy().describe()).isEqualTo("no — ticket TCK-1 is not a CHANGE ticket");
        TicketRecord change = TicketRecord.builder().ticketId("TCK-2").target("GB-500").hostCovers(true).build();
        // A ticket whose kind the host does not state is judged by the host's verdict on it.
        assertThat(evaluate(profile(List.of(), List.of(change), grant), request(null, List.of())).policy()
                .describe()).isEqualTo("yes — ticket TCK-2 covers GB-500");
    }

    @Test
    void aPolicyTheEngineCannotReadLeavesTheSatisfactionUnknown() {
        CompanyPolicy unread = CompanyPolicy.builder().policyId("LEGAL_HOLD").requirement("TWO_PERSON_REVIEW").build();

        assertThat(evaluate(profile(List.of(), List.of(), unread), request(null, List.of())).policy().satisfied())
                .isNull();
        assertThat(CompanyRecordsEvaluator.evaluate(null, request(null, List.of()), UTC))
                .isEqualTo(CompanyRecordsEvaluator.Evaluation.NONE);
    }

    private static CompanyRecordsEvaluator.Evaluation evaluate(FrictionProfile profile,
                                                               CompanyRecordsEvaluator.Request request) {
        return CompanyRecordsEvaluator.evaluate(profile, request, UTC);
    }

    private static CompanyRecordsEvaluator.Request request(Integer items, List<SessionDecisionRecord> session) {
        return new CompanyRecordsEvaluator.Request(AT, TARGET, items, session);
    }

    private static ApprovalRecord.ApprovalRecordBuilder approval(String id, Integer maxItems) {
        return ApprovalRecord.builder().approvalId(id).status("APPROVED").approver("pm-11").target("GB-500")
                .maxItems(maxItems).validFrom(AT.minus(Duration.ofDays(1))).validUntil(AT.plus(Duration.ofDays(1)));
    }

    private static FrictionProfile profile(List<ApprovalRecord> approvals, List<TicketRecord> tickets,
                                           CompanyPolicy... policies) {
        // The host looked up every kind of record, as the showcase host does for an export.
        return FrictionProfile.builder()
                .approvalRecords(new ArrayList<>(approvals))
                .ticketRecords(new ArrayList<>(tickets))
                .policies(new ArrayList<>(List.of(policies)))
                .checkedRecordKinds(new ArrayList<>(List.of("ASSIGNMENT", "APPROVAL", "TICKET", "ON_CALL", "ACCESS_HISTORY", "TRAVEL")))
                .build();
    }

    private static CompanyPolicy exportPolicy() {
        return CompanyPolicy.builder().policyId("EXPORT_APPROVAL").requirement("APPROVAL")
                .exceptions(new ArrayList<>(List.of(PolicyException.builder().kind("ASSIGNED").limit(500).build(),
                        PolicyException.builder().kind("TICKET_WHILE_ON_CALL").build())))
                .hostRequires(true).build();
    }

    private static CompanyPolicy documentPolicy() {
        return CompanyPolicy.builder().policyId("DOCUMENT_ACCESS_APPROVAL").requirement("TICKET")
                .exceptions(new ArrayList<>(List.of(PolicyException.builder().kind("ASSIGNED").build(),
                        PolicyException.builder().kind("RECENT_WORK").limit(90).build())))
                .build();
    }

    private static CompanyPolicy customerPolicy() {
        return CompanyPolicy.builder().policyId("CUSTOMER_ACCESS_APPROVAL").requirement("TICKET")
                .exceptions(new ArrayList<>(List.of(PolicyException.builder().kind("ACCOUNT_MANAGER").build())))
                .build();
    }

    private static SessionDecisionRecord exported(Instant at, String target, int items, String outcome) {
        return new SessionDecisionRecord(at, "POST", "/api/projects/x/exports", null, "EXPORT", outcome, target, items);
    }
}
