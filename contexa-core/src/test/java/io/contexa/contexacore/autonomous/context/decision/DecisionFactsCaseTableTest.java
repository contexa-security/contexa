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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.ApprovalRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.CompanyPolicy;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.PolicyException;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.TicketRecord;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W2-5 case table: for every case of the showcase, the company facts of a real measured step (read back from the
 * records the host stated in that step's prompt, see the resource's {@code source}) give the policy satisfaction and
 * the explaining record the review expects (docs/showcase/프롬프트-전면재검토.md section 6).
 */
class DecisionFactsCaseTableTest {

    private static final String TABLE = "/decision-facts/case-table.json";

    static Stream<Arguments> rows() throws IOException {
        try (InputStream input = DecisionFactsCaseTableTest.class.getResourceAsStream(TABLE)) {
            JsonNode table = new ObjectMapper().readTree(input);
            List<Arguments> rows = new ArrayList<>();
            table.get("rows").forEach(row -> rows.add(Arguments.of(
                    row.get("case").asText() + " step " + row.get("step").asInt(), row)));
            assertThat(rows).as("rows of the case table").hasSizeGreaterThanOrEqualTo(30);
            return rows.stream();
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("rows")
    void theCaseHasTheFactsTheReviewExpects(String label, JsonNode row) {
        FrictionProfile profile = profile(row.get("records"));
        CompanyRecordsEvaluator.Request request = request(row.get("request"), row.get("session"));
        JsonNode expected = row.get("expected");

        CompanyRecordsEvaluator.Evaluation evaluation = CompanyRecordsEvaluator.evaluate(profile, request, ZoneOffset.UTC);

        // Null: a fact the policy needs is not known (P2 correction 3).
        Boolean satisfied = expected.get("satisfied").isNull() ? null : expected.get("satisfied").asBoolean();
        assertThat(evaluation.policy().satisfied()).as(label + " policy satisfied").isEqualTo(satisfied);
        if (expected.has("unknown")) {
            assertThat(evaluation.policy().detail()).as(label + " what is not known")
                    .contains(expected.get("unknown").asText());
        }
        if (expected.has("reason")) {
            assertThat(evaluation.policy().reason()).as(label + " reason")
                    .isEqualTo(PolicyReason.valueOf(expected.get("reason").asText()));
        }
        if (expected.has("covering")) {
            assertThat(evaluation.covering()).as(label + " covering record").get()
                    .extracting(RecordCheck::recordId).asString().startsWith(expected.get("covering").asText() + "-");
        }
        else {
            assertThat(evaluation.covering()).as(label + " no covering record").isEmpty();
        }
        if (expected.path("claimFalse").asBoolean(false)) {
            assertThat(evaluation.tickets()).as(label + " claimed ticket").anyMatch(RecordCheck::claimFalse);
        }
        if (expected.has("trip")) {
            boolean trip = expected.get("trip").asBoolean();
            assertThat(profile.getTravel() != null && Boolean.TRUE.equals(DecisionFactsResolver.tripHoldsAddress(
                    profile.getTravel(), text(row.get("request"), "address"))))
                    .as(label + " a registered trip explains the network").isEqualTo(trip);
        }

        // The prompt's facts state the same satisfaction with its reason code.
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .requestObservedAt(request.at())
                .sessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder()
                        .sessionDecisions(new ArrayList<>(request.sessionDecisions())).build())
                .build();
        context.setFrictionProfile(profile);
        context.setResource(resource(row.get("request")));
        DecisionFacts facts = DecisionFactsResolver.resolve(context, null, ZoneOffset.UTC);
        assertThat(facts.fact(DecisionFactsResolver.POLICY_SATISFIED)).as(label + " PolicySatisfied fact").get()
                .satisfies(fact -> assertThat(fact.codes()).containsExactlyElementsOf(
                        evaluation.policy().satisfied() == null ? List.of()
                                : List.of(evaluation.policy().satisfied()
                                ? "POLICY_SATISFIED" : evaluation.policy().reason().code())));
    }

    private static FrictionProfile profile(JsonNode records) {
        FrictionProfile profile = FrictionProfile.builder().build();
        List<ApprovalRecord> approvals = new ArrayList<>();
        records.get("approvals").forEach(node -> approvals.add(ApprovalRecord.builder()
                .approvalId(text(node, "approvalId")).status(text(node, "status")).approver(text(node, "approver"))
                .purpose(text(node, "purpose")).maxItems(integer(node, "maxItems"))
                .validFrom(instant(node, "validFrom")).validUntil(instant(node, "validUntil"))
                .decidedAt(instant(node, "decidedAt")).hostCovers(node.path("hostCovers").asBoolean())
                .hostMismatches(strings(node.path("hostMismatches"))).build()));
        List<TicketRecord> tickets = new ArrayList<>();
        records.get("tickets").forEach(node -> tickets.add(TicketRecord.builder()
                .ticketId(text(node, "ticketId")).approver(text(node, "approver")).purpose(text(node, "purpose"))
                .validFrom(instant(node, "validFrom")).validUntil(instant(node, "validUntil"))
                .claimedByRequester(node.has("claimedByRequester") ? node.get("claimedByRequester").asBoolean() : null)
                .exists(node.has("exists") ? node.get("exists").asBoolean() : null)
                .hostCovers(node.path("hostCovers").asBoolean())
                .hostMismatches(strings(node.path("hostMismatches"))).build()));
        List<CompanyPolicy> policies = new ArrayList<>();
        records.get("policies").forEach(node -> {
            List<PolicyException> exceptions = new ArrayList<>();
            node.get("exceptions").forEach(exception -> exceptions.add(PolicyException.builder()
                    .kind(text(exception, "kind")).limit(integer(exception, "limit")).build()));
            policies.add(CompanyPolicy.builder().policyId(text(node, "policyId"))
                    .requirement(text(node, "requirement")).requiredTicketKind(text(node, "requiredTicketKind"))
                    .exceptions(exceptions).hostRequires(node.path("hostRequires").asBoolean()).build());
        });
        profile.setApprovalRecords(approvals);
        profile.setTicketRecords(tickets);
        profile.setPolicies(policies);
        profile.setCheckedRecordKinds(strings(records.path("checkedRecordKinds")));
        JsonNode onCall = records.get("onCall");
        if (onCall != null && !onCall.isNull()) {
            profile.setOnCall(CanonicalSecurityContext.OnCallRecord.builder().onCall(onCall.get("onCall").asBoolean())
                    .team(text(onCall, "team")).endsAt(instant(onCall, "endsAt")).build());
        }
        JsonNode travel = records.get("travel");
        if (travel != null && !travel.isNull()) {
            profile.setTravel(CanonicalSecurityContext.TravelRecord.builder().planId(text(travel, "planId"))
                    .city(text(travel, "city")).country(text(travel, "country")).network(text(travel, "network"))
                    .build());
        }
        JsonNode assignment = records.get("assignment");
        if (assignment != null && !assignment.isNull()) {
            profile.setAssignment(CanonicalSecurityContext.AssignmentRecord.builder()
                    .target(text(assignment, "target")).assigned(assignment.get("assigned").asBoolean())
                    .responsibility(text(assignment, "responsibility")).build());
        }
        JsonNode history = records.get("accessHistory");
        if (history != null && !history.isNull()) {
            profile.setAccessHistory(CanonicalSecurityContext.AccessHistoryRecord.builder()
                    .target(text(history, "target")).days(integer(history, "days"))
                    .windowDays(integer(history, "windowDays")).build());
        }
        return profile;
    }

    private static CompanyRecordsEvaluator.Request request(JsonNode request, JsonNode session) {
        List<SessionDecisionRecord> decisions = new ArrayList<>();
        session.forEach(step -> decisions.add(new SessionDecisionRecord(instant(step, "at"), null, null, null, null,
                text(step, "outcome"), text(step, "target"), integer(step, "items"))));
        return new CompanyRecordsEvaluator.Request(instant(request, "at"), text(request, "target"),
                integer(request, "items"), decisions);
    }

    /** A resource whose template binds the row's target, so that the facts read the same request. */
    private static CanonicalSecurityContext.Resource resource(JsonNode request) {
        String target = text(request, "target");
        CanonicalSecurityContext.Resource.ResourceBuilder resource = CanonicalSecurityContext.Resource.builder()
                .requestedItems(integer(request, "items"));
        if (target != null) {
            String name = target.substring(0, target.indexOf('='));
            String value = target.substring(target.indexOf('=') + 1);
            resource.pathFamily("/api/x/{" + name + "}").requestPath("/api/x/" + value);
        }
        return resource.build();
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static Integer integer(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asInt();
    }

    private static Instant instant(JsonNode node, String field) {
        String value = text(node, field);
        return value == null ? null : Instant.parse(value);
    }

    private static List<String> strings(JsonNode node) {
        List<String> values = new ArrayList<>();
        if (node != null && node.isArray()) {
            node.forEach(value -> values.add(value.asText()));
        }
        return values;
    }
}
