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

import io.contexa.contexacore.autonomous.baseline.BaselineView;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.ApprovalRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.CompanyPolicy;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.PolicyException;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.CurrentLearningContextSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
import io.contexa.contexacore.autonomous.learning.evidence.RetrievedBehaviorEvidence;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/** W2-5: the decision facts of a request, computed once from the context and the evidence. */
class DecisionFactsResolverTest {

    private static final ZoneId UTC = ZoneOffset.UTC;
    /** A Wednesday, 03:17 on the event clock. */
    private static final Instant AT = Instant.parse("2026-09-30T03:17:00Z");

    @Test
    void anExportAtDawnToAnUnusualProjectStatesEachDifferenceWithHowOftenItWasSeen() {
        // Case A3: administrator A exports 4,831 documents of GB-500 at 03:17 without an approval.
        CanonicalSecurityContext context = export(4831, friction(List.of()));

        DecisionFacts facts = DecisionFactsResolver.resolve(context, evidence(current("CRITICAL", "Chrome/140",
                "10.40.12.0/24"), personal(), adminView()), UTC);

        assertThat(facts.facts()).extracting(DecisionFact::id, DecisionFact::name).containsExactly(
                tuple("F1", "DeviationsFromBaseline"),
                tuple("F2", "SameAsBaseline"),
                tuple("F3", "Policy"),
                tuple("F4", "PolicySatisfied"),
                tuple("F5", "Assignment"),
                tuple("F6", "Ticket"),
                tuple("F7", "Travel"),
                tuple("F8", "RepeatInSession"));
        assertThat(value(facts, "DeviationsFromBaseline")).isEqualTo("4 of 10 compared -> "
                + "time 03 seen 0 of 25 (unexplained); target GB-500 seen 0 of 25 (unexplained); "
                + "class CRITICAL seen 0 of 25 (unexplained); "
                + "size 4,831 items, usual up to 29 items per export (median 17, 5 exports) (unexplained)");
        assertThat(facts.fact("DeviationsFromBaseline").orElseThrow().codes()).containsExactly(
                "DEVIATION_TIME", "DEVIATION_TARGET", "DEVIATION_RESOURCE_CLASS", "DEVIATION_SIZE");
        assertThat(value(facts, "SameAsBaseline")).isEqualTo("day, network, device, login method, action, rate");
        assertThat(value(facts, "Policy")).isEqualTo("EXPORT_APPROVAL requires a covering approval "
                + "(exceptions: assigned target up to 500 items; ticket while on call)");
        assertThat(value(facts, "PolicySatisfied")).isEqualTo("no — no approval for GB-500");
        assertThat(facts.fact("PolicySatisfied").orElseThrow().codes())
                .containsExactly("POLICY_NOT_SATISFIED_NO_RECORD");
        assertThat(value(facts, "Assignment")).isEqualTo("not assigned to GB-500; worked on GB-500 on 0 of the last 30 days");
        assertThat(value(facts, "Ticket")).isEqualTo("no ticket found");
        assertThat(value(facts, "Travel")).isEqualTo("no registered trip holds the request address");
        assertThat(value(facts, "RepeatInSession")).isEqualTo("first EXPORT of GB-500 in this session");
        assertThat(facts.unknown()).containsExactly("OnCall", "RoleScope", "PeerCohort");
        assertThat(facts.unexplained()).extracting(Deviation::dimension).containsExactly(DeviationDimension.TIME,
                DeviationDimension.TARGET, DeviationDimension.RESOURCE_CLASS, DeviationDimension.SIZE);
        assertThat(facts.fact("DeviationsFromBaseline").orElseThrow().source()).isEqualTo(DecisionFact.COMPUTED);
        assertThat(facts.fact("Policy").orElseThrow().source()).isEqualTo(DecisionFact.HOST);
    }

    @Test
    void aValidApprovalExplainsTheDifferencesOfTheWorkItCovers() {
        // Case A3T: the same export under an approval of 5,000 items decided before the request.
        ApprovalRecord approval = ApprovalRecord.builder().approvalId("APR-1").status("APPROVED").approver("pm-11")
                .purpose("PROJECT_TRANSFER").target("GB-500").maxItems(5000).usedItems(0)
                .validFrom(AT.minus(Duration.ofDays(1))).validUntil(AT.plus(Duration.ofDays(1))).hostCovers(true)
                .build();
        CanonicalSecurityContext context = export(4831, friction(List.of(approval)));

        DecisionFacts facts = DecisionFactsResolver.resolve(context, evidence(current("CRITICAL", "Chrome/140",
                "10.40.12.0/24"), personal(), adminView()), UTC);

        assertThat(value(facts, "DeviationsFromBaseline")).contains("time 03 seen 0 of 25 (explained by APR-1)")
                .contains("size 4,831 items, usual up to 29 items per export (median 17, 5 exports) (explained by APR-1)");
        assertThat(facts.unexplained()).isEmpty();
        assertThat(facts.fact("DeviationsFromBaseline").orElseThrow().recordIds()).containsExactly("APR-1");
        assertThat(value(facts, "PolicySatisfied")).isEqualTo(
                "yes — approval APR-1 PROJECT_TRANSFER up to 5,000, requested 4,831, decision time not recorded");
        assertThat(value(facts, "Approval")).isEqualTo("APR-1 by pm-11, APPROVED, PROJECT_TRANSFER, GB-500, "
                + "up to 5,000 items, used 0 before this request, valid 09-29 03:17..10-01 03:17, "
                + "decision time not recorded — covers this request");
        assertThat(facts.fact("Approval").orElseThrow().codes()).containsExactly("APPROVAL_COVERS");
        assertThat(facts.fact("Approval").orElseThrow().id()).isEqualTo("F5");

        // Without the host's count of the approval's use, it is not known to cover the work and explains nothing.
        approval.setUsedItems(null);
        DecisionFacts unreported = DecisionFactsResolver.resolve(export(4831, friction(List.of(approval))),
                evidence(current("CRITICAL", "Chrome/140", "10.40.12.0/24"), personal(), adminView()), UTC);
        assertThat(value(unreported, "PolicySatisfied")).isEqualTo("unknown — not known: approval APR-1: the items "
                + "exported under it outside this session (the host does not report them)");
        assertThat(value(unreported, "Approval")).endsWith(" — not known whether it covers: the items exported under it "
                + "outside this session (the host does not report them)");
        assertThat(value(unreported, "DeviationsFromBaseline")).contains("time 03 seen 0 of 25 (unexplained)");
    }

    @Test
    void aRecordTheHostDidNotLookUpIsNotKnownRatherThanAbsent() {
        FrictionProfile friction = friction(List.of());
        friction.setCheckedRecordKinds(new ArrayList<>(List.of("APPROVAL", "ASSIGNMENT", "ACCESS_HISTORY")));

        DecisionFacts facts = DecisionFactsResolver.resolve(export(10, friction), evidence(current("CRITICAL",
                "Chrome/140", "10.40.12.0/24"), personal(), adminView()), UTC);

        assertThat(facts.fact("Ticket")).isEmpty();
        assertThat(facts.fact("Travel")).isEmpty();
        assertThat(facts.unknown()).contains("Ticket", "Travel");
    }

    @Test
    void aTripIsComparedWithTheRequestAddressInIpv4AndIpv6AndOtherwiseNotKnown() {
        CanonicalSecurityContext.TravelRecord v6 = CanonicalSecurityContext.TravelRecord.builder().planId("TRV-6")
                .network("2001:db8:1::/64").build();
        assertThat(DecisionFactsResolver.tripHoldsAddress(v6, "2001:db8:1::5")).isTrue();
        assertThat(DecisionFactsResolver.tripHoldsAddress(v6, "2001:db8:2::5")).isFalse();
        assertThat(DecisionFactsResolver.tripHoldsAddress(v6, "198.51.100.7")).isNull();
        assertThat(DecisionFactsResolver.tripHoldsAddress(v6, "laptop.example")).isNull();

        CanonicalSecurityContext.TravelRecord noNetwork = CanonicalSecurityContext.TravelRecord.builder()
                .planId("TRV-2").city("Singapore").country("SG").build();
        DecisionFacts facts = DecisionFactsResolver.resolve(read("198.51.100.7", noNetwork), evidence(current(
                "INTERNAL", "Chrome/140", "198.51.100.0/24"), personal(), adminView()), UTC);
        assertThat(value(facts, "Travel"))
                .isEqualTo("trip TRV-2 to Singapore SG, whether it holds the request address is not known");
        assertThat(value(facts, "DeviationsFromBaseline")).contains("network 198.51.100.0/24 seen 0 of 25 (unexplained)");
    }

    @Test
    void theClosestPastRecordIsComparedOnWhatTheSearchLeavesFree() {
        // Every past record of the resource shares its action, class and path family: only the hour, the login
        // method and the browser tell the closest one from the request (P2 correction 3).
        RetrievedBehaviorEvidence past = new RetrievedBehaviorEvidence(LearningEvidenceScope.PERSONAL, "admin-a",
                "behavior", "event-1", 0.98, "10.40.12.10", "10.40.12.0/24", "/api/projects/PLM-OPS/exports",
                "/api/projects/{projectKey}/exports", "14", "2", "Chrome/140", "WINDOWS", "PASSWORD", "EXPORT",
                "CRITICAL", "HIGH", null, null, null, null);
        LearningContextEvidence evidence = new LearningContextEvidence(current("CRITICAL", "Chrome/140",
                "10.40.12.0/24"), personal(), null, List.of(past), List.of(), null, List.of(), List.of(), List.of(),
                adminView());

        DecisionFacts facts = DecisionFactsResolver.resolve(export(10, friction(List.of())), evidence, UTC);

        assertThat(evidence.currentRequestClosestObservedOverlap()).isEqualTo("5/6");
        assertThat(value(facts, "DeviationsFromBaseline"))
                .contains("closest past record of this resource matches 2 of 3 on time, login method and browser");
    }

    @Test
    void aNetworkIsExplainedOnlyByARegisteredTripThatHoldsTheAddress() {
        // Cases A1 and A1T: engineer K reads a drawing from an outside network, with and without a registered trip.
        CanonicalSecurityContext outside = read("203.0.113.9", null);
        DecisionFacts a1 = DecisionFactsResolver.resolve(outside, evidence(current("INTERNAL", "Safari/17",
                "203.0.113.0/24"), personal(), adminView()), UTC);
        assertThat(value(a1, "DeviationsFromBaseline"))
                .contains("network 203.0.113.0/24 seen 0 of 25 (unexplained)")
                .contains("device Safari/17 on WINDOWS seen 0 of 25 (unexplained)");
        assertThat(a1.unexplained()).extracting(Deviation::dimension)
                .containsExactly(DeviationDimension.NETWORK, DeviationDimension.DEVICE);
        // A drawing is read once in the usual course: a new document is not compared as a target, while the usual
        // projects make an export's project comparable.
        assertThat(a1.deviations()).filteredOn(deviation -> deviation.dimension() == DeviationDimension.TARGET)
                .singleElement().extracting(Deviation::compared).isEqualTo(false);

        CanonicalSecurityContext.TravelRecord trip = CanonicalSecurityContext.TravelRecord.builder().planId("TRV-1")
                .city("Singapore").country("SG").network("198.51.100.0/24").build();
        DecisionFacts a1t = DecisionFactsResolver.resolve(read("198.51.100.7", trip), evidence(current("INTERNAL",
                "Chrome/140", "198.51.100.0/24"), personal(), adminView()), UTC);
        assertThat(value(a1t, "DeviationsFromBaseline"))
                .contains("network 198.51.100.0/24 seen 0 of 25 (explained by trip TRV-1)");
        assertThat(value(a1t, "Travel"))
                .isEqualTo("trip TRV-1 to Singapore SG, network 198.51.100.0/24 holds the request address");
        assertThat(a1t.fact("Travel").orElseThrow().codes()).containsExactly("TRAVEL_EXPLAINS_NETWORK");

        // A trip whose network does not hold the address explains nothing.
        assertThat(DecisionFactsResolver.tripHoldsAddress(trip, "203.0.113.9")).isFalse();
        assertThat(DecisionFactsResolver.tripHoldsAddress(trip, "198.51.100.200")).isTrue();
    }

    @Test
    void withoutAUsualBehaviourTheDifferencesAreUnknown() {
        // Case S08: an employee without a learned template.
        DecisionFacts facts = DecisionFactsResolver.resolve(export(10, friction(List.of())), null, UTC);

        assertThat(facts.fact("DeviationsFromBaseline")).isEmpty();
        assertThat(facts.unknown()).contains("DeviationsFromBaseline", "SameAsBaseline");
        assertThat(facts.deviations()).allSatisfy(deviation -> {
            assertThat(deviation.compared()).isFalse();
            assertThat(deviation.explanation()).isEqualTo(Deviation.Explanation.UNKNOWN);
        });
        assertThat(facts.unexplained()).isEmpty();
    }

    @Test
    void repeatsOfTheSameActionAndTheRateOfTheLastHourAreCountedFromTheSession() {
        // Case S11 second step: one export of 480 items a minute before; the busiest hour before held 3 requests.
        List<SessionDecisionRecord> session = new ArrayList<>();
        session.add(new SessionDecisionRecord(AT.minusSeconds(240), "GET", "/api/projects", null, "READ", "ALLOW"));
        session.add(new SessionDecisionRecord(AT.minusSeconds(180), "GET", "/api/projects", null, "READ", "ALLOW"));
        session.add(new SessionDecisionRecord(AT.minusSeconds(120), "GET", "/api/projects", null, "READ", "ALLOW"));
        session.add(new SessionDecisionRecord(AT.minusSeconds(60), "POST", "/api/projects/GB-500/exports", null,
                "EXPORT", "ALLOW", "projectKey=GB-500", 480));
        CanonicalSecurityContext context = export(480, friction(List.of()));
        context.getSessionNarrativeProfile().setSessionDecisions(session);

        DecisionFacts facts = DecisionFactsResolver.resolve(context, evidence(current("CRITICAL", "Chrome/140",
                "10.40.12.0/24"), personal(), adminView()), UTC);

        assertThat(value(facts, "RepeatInSession")).isEqualTo(
                "2nd EXPORT in this session, 1 earlier of GB-500; 480 items exported to GB-500 before this request");
        assertThat(facts.fact("RepeatInSession").orElseThrow().codes()).containsExactly("REPEAT_IN_SESSION");
        assertThat(value(facts, "DeviationsFromBaseline"))
                .contains("rate 5 requests in the last hour, usual at most 3 in one hour (unexplained)");
    }

    @Test
    void theScopeGroupTheDataConflictsAndTheCohortAreStatedWhenTheyAreKnown() {
        CanonicalSecurityContext context = export(10, friction(List.of()));
        context.setRoleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                .currentActionFamily("EXPORT").expectedActionFamilies(new ArrayList<>(List.of("READ")))
                .actionFamilyDrift(true).build());
        Map<String, String> sources = new LinkedHashMap<>();
        sources.put("request", "tenant-a");
        sources.put("account", "tenant-b");
        context.setDataConflicts(new ArrayList<>(List.of(CanonicalSecurityContext.DataConflict.builder()
                .field("tenantId").sources(sources).build())));
        context.setPeerCohortProfile(CanonicalSecurityContext.PeerCohortProfile.builder().cohortId("C1")
                .preferredActionFamilies(new ArrayList<>(List.of("READ"))).build());

        DecisionFacts facts = DecisionFactsResolver.resolve(context, null, UTC);

        assertThat(value(facts, "RoleScope")).isEqualTo("action EXPORT outside the scope group's actions (READ)");
        assertThat(facts.fact("RoleScope").orElseThrow().codes()).containsExactly("ROLE_SCOPE_OUTSIDE");
        assertThat(value(facts, "DataConflicts")).isEqualTo("tenantId (request tenant-a, account tenant-b)");
        assertThat(facts.fact("DataConflicts").orElseThrow().codes()).containsExactly("TENANT_CONFLICT");
        assertThat(value(facts, "PeerCohort")).isEqualTo("cohort C1: action EXPORT outside the cohort's usual actions");
        assertThat(facts.unknown()).doesNotContain("RoleScope", "PeerCohort");
    }

    private static String value(DecisionFacts facts, String name) {
        return facts.fact(name).orElseThrow().value();
    }

    private static CanonicalSecurityContext export(int items, FrictionProfile friction) {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .requestObservedAt(AT)
                .resource(CanonicalSecurityContext.Resource.builder()
                        .pathFamily("/api/projects/{projectKey}/exports").requestPath("/api/projects/GB-500/exports")
                        .requestedItems(items).actionFamily("EXPORT").build())
                .session(CanonicalSecurityContext.Session.builder().clientIp("10.40.12.160").build())
                .location(CanonicalSecurityContext.Location.builder().networkZone("CORPORATE").build())
                .sessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder().build())
                .build();
        context.setFrictionProfile(friction);
        return context;
    }

    private static CanonicalSecurityContext read(String clientIp, CanonicalSecurityContext.TravelRecord trip) {
        FrictionProfile friction = FrictionProfile.builder()
                .assignment(CanonicalSecurityContext.AssignmentRecord.builder().target("HX-310").assigned(true).build())
                .travel(trip)
                .checkedRecordKinds(new ArrayList<>(List.of("ASSIGNMENT", "TICKET", "ACCESS_HISTORY", "TRAVEL")))
                .build();
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .requestObservedAt(AT.plus(Duration.ofHours(7)))
                .resource(CanonicalSecurityContext.Resource.builder().pathFamily("/api/documents/{documentKey}")
                        .requestPath("/api/documents/HX-310-DWG-00003").actionFamily("READ").build())
                .session(CanonicalSecurityContext.Session.builder().clientIp(clientIp).build())
                .location(CanonicalSecurityContext.Location.builder()
                        .networkZone(trip != null ? "TRAVEL" : "EXTERNAL").build())
                .sessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder().build())
                .build();
        context.setFrictionProfile(friction);
        return context;
    }

    private static FrictionProfile friction(List<ApprovalRecord> approvals) {
        return FrictionProfile.builder()
                .approvalRecords(new ArrayList<>(approvals))
                .policies(new ArrayList<>(List.of(CompanyPolicy.builder().policyId("EXPORT_APPROVAL")
                        .requirement("APPROVAL")
                        .exceptions(new ArrayList<>(List.of(PolicyException.builder().kind("ASSIGNED").limit(500).build(),
                                PolicyException.builder().kind("TICKET_WHILE_ON_CALL").build())))
                        .hostRequires(true).build())))
                .assignment(CanonicalSecurityContext.AssignmentRecord.builder().target("GB-500").assigned(false).build())
                .accessHistory(CanonicalSecurityContext.AccessHistoryRecord.builder().target("GB-500").days(0)
                        .windowDays(30).build())
                .checkedRecordKinds(new ArrayList<>(List.of("ASSIGNMENT", "APPROVAL", "TICKET", "ON_CALL", "ACCESS_HISTORY", "TRAVEL")))
                .build();
    }

    private static CurrentLearningContextSnapshot current(String resourceClass, String browser, String network) {
        return new CurrentLearningContextSnapshot("3", "3", network, browser, "WINDOWS",
                "/api/projects/{projectKey}/exports", "PASSWORD", "EXPORT", resourceClass);
    }

    private static BaselineEvidenceSnapshot personal() {
        Map<String, Long> frequencies = new LinkedHashMap<>();
        frequencies.put("ip:10.40.12.0/24", 25L);
        frequencies.put("device:Chrome/140 on WINDOWS", 25L);
        frequencies.put("auth:PASSWORD", 25L);
        return new BaselineEvidenceSnapshot(LearningEvidenceScope.PERSONAL, true, true, 25L, null,
                List.of("10.40.12.0/24"), List.of(), List.of(), List.of("Chrome/140"), List.of("WINDOWS"), List.of(),
                List.of("PASSWORD"), List.of(), List.of(), "", BaselineEvidenceStatus.AVAILABLE, "",
                List.of("Chrome/140 on WINDOWS"), frequencies);
    }

    @Test
    void aDayOfTheWeekIsCountedAgainstTheObservationsOfTheWeeksItWasReadFrom() {
        // A Sunday request: the days of the week read 50 observations of several weeks, the window 25 (W2-3 correction).
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .requestObservedAt(AT.plus(Duration.ofDays(4)))
                .resource(CanonicalSecurityContext.Resource.builder().pathFamily("/api/documents/{documentKey}")
                        .requestPath("/api/documents/HX-310-DWG-00003").actionFamily("READ").build())
                .session(CanonicalSecurityContext.Session.builder().clientIp("10.40.12.160").build())
                .location(CanonicalSecurityContext.Location.builder().networkZone("CORPORATE").build())
                .sessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder().build())
                .build();
        context.setFrictionProfile(FrictionProfile.builder().build());
        BaselineView admin = adminView();
        BaselineView view = new BaselineView(admin.state(), admin.learnedUpdates(), admin.observations(),
                admin.daysCovered(), admin.windowDays(), admin.windowBasis(), admin.usualHours(), admin.seenHours(),
                admin.usualDays(), admin.seenDays(), admin.usualTargets(), admin.actionCounts(),
                admin.readWriteExportRatio(), admin.exportSize(), admin.resourceClasses(), admin.requestsPerActiveHour(),
                admin.usualSessionMinutes(), admin.privilegedActions(), admin.knownRareTasks(), admin.usualNetworks(),
                admin.usualDevices(), admin.usualBrowsers(), admin.usualOperatingSystems(), admin.usualLoginMethods(),
                admin.evidenceGrade(), admin.evidenceCauses(),
                new BaselineView.Counts(admin.counts().hours(), Map.of(1, 10, 2, 10, 3, 10, 4, 10, 5, 10),
                        admin.counts().targets(), admin.counts().busiestActiveHourRequests(), 50));

        DecisionFacts facts = DecisionFactsResolver.resolve(context, evidence(current("CRITICAL", "Chrome/140",
                "10.40.12.0/24"), personal(), view), UTC);

        assertThat(value(facts, "DeviationsFromBaseline")).contains("day Sun seen 0 of 50 (unexplained)");
    }

    /** Administrator A's usual week: 25 observations on weekdays 09-17, project PLM-OPS, 20 reads and 5 exports. */
    private static BaselineView adminView() {
        Map<Integer, Integer> hours = new LinkedHashMap<>();
        for (int hour = 9; hour <= 17; hour++) {
            hours.put(hour, hour == 15 ? 1 : 3);
        }
        Map<Integer, Integer> days = Map.of(1, 5, 2, 5, 3, 5, 4, 5, 5, 5);
        Map<String, Integer> actions = new LinkedHashMap<>();
        actions.put("READ", 20);
        actions.put("EXPORT", 5);
        return new BaselineView(BaselineView.State.ESTABLISHED, 25L, 25, 5, 7, "the last 7 days hold 25 observations",
                List.of(9, 10, 11, 12, 13, 14, 16, 17), List.of(9, 10, 11, 12, 13, 14, 15, 16, 17),
                List.of(1, 2, 3, 4, 5), List.of(1, 2, 3, 4, 5), List.of("projectKey=PLM-OPS"), actions, "80:0:20",
                new BaselineView.ExportSize(5, 17, 29), List.of("INTERNAL=25"), 1.19, null, 0, List.of(),
                List.of("10.40.12.0/24"), List.of("Chrome/140 on WINDOWS"), List.of("Chrome/140"), List.of("WINDOWS"),
                List.of("PASSWORD"), BaselineView.EvidenceGrade.STRONG, List.of(),
                new BaselineView.Counts(hours, days, Map.of("projectKey=PLM-OPS", 25), 3));
    }

    private static LearningContextEvidence evidence(CurrentLearningContextSnapshot current,
                                                    BaselineEvidenceSnapshot personal, BaselineView view) {
        return new LearningContextEvidence(current, personal, null, List.of(), List.of(), null, List.of(), List.of(),
                List.of(), view);
    }
}
