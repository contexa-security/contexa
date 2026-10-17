package io.contexa.showcase.portal.reactivity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W6-1 (P6-CHANGE-2, plan 8.4, metric C4): a lab run that changes one condition is compared fact by fact with the
 * designed run of the same case, on the lines control D read from the seals with the OSS prompt parser. Only the facts
 * the condition should change may change; run identity inside values and the lines that differ in every run are left
 * out (the prototype is prompt-audit/w06/delivery.py).
 */
class DeliveryEvaluatorTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final DeliveryEvaluator evaluator = DeliveryEvaluator.fromResources();

    @Test
    void aTimeChangeThatOnlyMovesTheTimeLinesIsDelivered() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Time", "value": "03:17 Wed"},
                           {"label": "DeviationsFromBaseline", "value": "1 of 8 compared -> time 03"},
                           {"label": "OnCall", "value": "not on call"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Time", "value": "14:05 Wed"},
                           {"label": "DeviationsFromBaseline", "value": "0 of 8 compared"},
                           {"label": "OnCall", "value": "not on call"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "timeSlot");

        assertThat(delivery.delivered()).containsExactly("DeviationsFromBaseline", "Time");
        assertThat(delivery.unexpected()).isEmpty();
        assertThat(delivery.passed()).isTrue();
    }

    @Test
    void aFactTheConditionShouldNotChangeIsUnexpected() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Time", "value": "03:17 Wed"}, {"label": "Device", "value": "usual laptop"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Time", "value": "14:05 Wed"}, {"label": "Device", "value": "new phone"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "timeSlot");

        assertThat(delivery.unexpected()).containsExactly("Device");
        assertThat(delivery.passed()).isFalse();
    }

    @Test
    void runIdentityInsideAValueIsNotAChange() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Subject", "value": "v107dabe3a78d-adm-a in tenant-107dabe3a78d"},
                           {"label": "Approval", "value": "APR-107dabe3a78d-1 by pm-11"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Subject", "value": "v9f03c1e2a7b1-adm-a in tenant-9f03c1e2a7b1"},
                           {"label": "Approval", "value": "APR-9f03c1e2a7b1-1 by pm-11"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "invariant");

        assertThat(delivery.changed()).isEmpty();
        assertThat(delivery.passed()).isTrue();
    }

    @Test
    void aLineThatDiffersInEveryRunIsLeftOut() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "RequestId", "value": "a"}, {"label": "Time", "value": "03:17 Wed"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "RequestId", "value": "b"}, {"label": "Time", "value": "03:17 Wed"}]}""");

        assertThat(evaluator.compare(base, variant, "timeSlot").changed()).isEmpty();
    }

    @Test
    void aConditionThatChangedNothingIsNotDelivered() throws Exception {
        PromptFacts same = facts("""
                {"lines": [{"label": "Time", "value": "03:17 Wed"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(same, same, "timeSlot");

        assertThat(delivery.delivered()).isEmpty();
        assertThat(delivery.passed()).isFalse();
    }

    @Test
    void theChangedLineSaysTheRequestedValue() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Time", "value": "Wed 03:17"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Time", "value": "Wed 14:20"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "timeSlot", "AFTERNOON");

        assertThat(delivery.valueMatches()).isTrue();
        assertThat(delivery.passed()).isTrue();
    }

    @Test
    void aChangedLineThatDoesNotSayTheRequestedValueIsNotDelivered() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Time", "value": "Wed 03:17"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Time", "value": "Wed 20:30"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "timeSlot", "AFTERNOON");

        assertThat(delivery.valueMatches()).isFalse();
        assertThat(delivery.passed()).isFalse();
    }

    @Test
    void aCountIsMatchedTheWayTheRendererWritesIt() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Size", "value": "40 items"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Size", "value": "4,831 items"}]}""");

        assertThat(evaluator.compare(base, variant, "items", "4831").valueMatches()).isTrue();
    }

    @Test
    void anAbsentLineMeetsANegatedValue() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "PolicySatisfied", "value": "yes - approval APR-1"},
                           {"label": "Approval", "value": "APR-1 by pm-11 - covers this request"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "PolicySatisfied", "value": "no - no approval for GB-500"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "approval", "False");

        assertThat(delivery.valueMatches()).isTrue();
        assertThat(delivery.passed()).isTrue();
    }

    @Test
    void withoutARequestedValueNoValueIsChecked() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Time", "value": "Wed 03:17"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Time", "value": "Wed 20:30"}]}""");

        assertThat(evaluator.compare(base, variant, "timeSlot").valueMatches()).isNull();
    }

    /** W7-13: the lab result's "the other lines stayed": the variant's compared lines that did not change. */
    @Test
    void theLinesThatStayedAreCountedWithoutTheVolatileOnes() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Time", "value": "Wed 03:17"}, {"label": "Device", "value": "Edge/140"},
                           {"label": "UntrustedText1", "value": "a"}, {"label": "UntrustedText1", "value": "b"},
                           {"label": "RequestId", "value": "r-1"},
                           {"label": "Ticket", "value": "no ticket found"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Time", "value": "Wed 14:20"}, {"label": "Device", "value": "Edge/140"},
                           {"label": "UntrustedText1", "value": "a"}, {"label": "UntrustedText1", "value": "b"},
                           {"label": "RequestId", "value": "r-1"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "timeSlot");

        assertThat(delivery.changed()).containsExactly("Ticket", "Time");
        assertThat(delivery.unchangedLines()).as("Device and the two untrusted text lines; RequestId is volatile")
                .isEqualTo(3);
    }

    @Test
    void aTimeChangeMayMoveTheFactsThatFollowTheRequestTime() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Time", "value": "03:17 Wed"},
                           {"label": "UsualHours", "value": "10-11, 13-14"},
                           {"label": "PastRecord1", "value": "09-29 Tue 13:52 (13 h before this request)"},
                           {"label": "OnCall", "value": "not on call"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Time", "value": "14:20 Wed"},
                           {"label": "UsualHours", "value": "09-11, 13-14"},
                           {"label": "PastRecord1", "value": "09-29 Tue 13:52 (24 h before this request)"},
                           {"label": "OnCall", "value": "not on call"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "timeSlot");

        assertThat(delivery.delivered()).containsExactly("Time");
        assertThat(delivery.derived()).containsExactly("PastRecord1", "UsualHours");
        assertThat(delivery.unexpected()).isEmpty();
        assertThat(delivery.passed()).isTrue();
    }

    @Test
    void aFactDerivedFromAnotherConditionIsStillUnexpected() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Network", "value": "10.40.12.0/24 zone CORPORATE"},
                           {"label": "ResourceClass", "value": "CRITICAL"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Network", "value": "203.0.113.0/24 zone EXTERNAL"},
                           {"label": "ResourceClass", "value": "NORMAL"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "place");

        assertThat(delivery.derived()).isEmpty();
        assertThat(delivery.unexpected()).containsExactly("ResourceClass");
        assertThat(delivery.passed()).isFalse();
    }

    @Test
    void aConditionThatChangedOnlyDerivedFactsIsNotDelivered() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Target", "value": "Export of 4831 documents"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Target", "value": "Export of 40 documents"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "items");

        assertThat(delivery.derived()).containsExactly("Target");
        assertThat(delivery.delivered()).isEmpty();
        assertThat(delivery.passed()).as("the expected Size line did not change").isFalse();
    }

    @Test
    void everyDerivedFactOfTheResourceHasItsReason() throws Exception {
        JsonNode derived;
        try (var stream = DeliveryEvaluator.class.getResourceAsStream("/reactivity/delivery-expected.json")) {
            derived = JSON.readTree(stream).path("derived");
        }
        assertThat(derived.size()).as("N-DLV-6 adds onCall").isEqualTo(7);
        derived.fields().forEachRemaining(condition -> {
            assertThat(condition.getValue().path("because").asText()).as(condition.getKey()).isNotBlank();
            assertThat(condition.getValue().path("facts").size()).as(condition.getKey()).isPositive();
        });
    }

    /**
     * N-INJ-3: from v20.24 the target's business label, which states the item count, is an UNTRUSTED TEXT line (a
     * v20.23 seal states it on the Target line).
     */
    @Test
    void anItemsChangeMayMoveTheBusinessLabelLine() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Size", "value": "4,831 items"},
                           {"label": "UntrustedText1",
                            "value": "source=business label (host text); \\"Export of 4831 documents\\""}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Size", "value": "40 items"},
                           {"label": "UntrustedText1",
                            "value": "source=business label (host text); \\"Export of 40 documents\\""}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "items");

        assertThat(delivery.delivered()).containsExactly("Size");
        assertThat(delivery.derived()).containsExactly("UntrustedText1");
        assertThat(delivery.unexpected()).isEmpty();
        assertThat(delivery.passed()).isTrue();
    }

    @Test
    void aRecordConditionTheOperationDoesNotLookUpIsComparedAsInvariant() throws Exception {
        PromptFacts base = facts("""
                {"checkedRecordKinds": ["ASSIGNMENT", "TICKET", "ACCESS_HISTORY", "TRAVEL"],
                 "lines": [{"label": "Subject", "value": "lab-adm-a"},
                           {"label": "PolicySatisfied", "value": "no - no ticket covers this read"}]}""");
        PromptFacts variant = facts("""
                {"checkedRecordKinds": ["ASSIGNMENT", "TICKET", "ACCESS_HISTORY", "TRAVEL"],
                 "lines": [{"label": "Subject", "value": "lab-adm-b"},
                           {"label": "PolicySatisfied", "value": "no - no ticket covers this read"}]}""");

        DeliveryEvaluator.Delivery approval = evaluator.compare(base, variant, "approval", "true");
        DeliveryEvaluator.Delivery onCall = evaluator.compare(base, variant, "onCall", "true");

        assertThat(approval.notLookedUp()).isEqualTo("APPROVAL");
        assertThat(approval.valueMatches()).as("the value cannot reach the prompt").isNull();
        assertThat(approval.passed()).isTrue();
        assertThat(onCall.notLookedUp()).isEqualTo("ON_CALL");
        assertThat(onCall.passed()).isTrue();
    }

    @Test
    void aChangedFactOfAConditionNotLookedUpFails() throws Exception {
        PromptFacts base = facts("""
                {"checkedRecordKinds": ["ASSIGNMENT", "TICKET", "ACCESS_HISTORY", "TRAVEL"],
                 "lines": [{"label": "OnCall", "value": "not on call"}]}""");
        PromptFacts variant = facts("""
                {"checkedRecordKinds": ["ASSIGNMENT", "TICKET", "ACCESS_HISTORY", "TRAVEL"],
                 "lines": [{"label": "OnCall", "value": "on call (ops)"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "onCall", "true");

        assertThat(delivery.unexpected()).containsExactly("OnCall");
        assertThat(delivery.passed()).isFalse();
    }

    @Test
    void aRecordConditionTheOperationLooksUpIsComparedAsBefore() throws Exception {
        PromptFacts base = facts("""
                {"checkedRecordKinds": ["ASSIGNMENT", "APPROVAL", "TICKET", "ON_CALL", "ACCESS_HISTORY", "TRAVEL"],
                 "lines": [{"label": "PolicySatisfied", "value": "no - no approval for GB-500"}]}""");
        PromptFacts variant = facts("""
                {"checkedRecordKinds": ["ASSIGNMENT", "APPROVAL", "TICKET", "ON_CALL", "ACCESS_HISTORY", "TRAVEL"],
                 "lines": [{"label": "PolicySatisfied", "value": "yes - approval APR-1"},
                           {"label": "Approval", "value": "APR-1 by pm-11 - covers this request"}]}""");

        DeliveryEvaluator.Delivery delivered = evaluator.compare(base, variant, "approval", "true");
        DeliveryEvaluator.Delivery missed = evaluator.compare(base, base, "approval", "true");

        assertThat(delivered.notLookedUp()).isNull();
        assertThat(delivered.delivered()).containsExactly("Approval", "PolicySatisfied");
        assertThat(delivered.passed()).isTrue();
        assertThat(missed.passed()).as("a looked-up approval that changed nothing is not delivered").isFalse();
    }

    @Test
    void aClaimedTicketIsComparedAsInvariantWhereTheOperationDoesNotReadClaims() throws Exception {
        PromptFacts read = facts("""
                {"actionFamily": "READ", "lines": [{"label": "Ticket", "value": "no ticket found"}]}""");
        PromptFacts export = facts("""
                {"actionFamily": "EXPORT", "lines": [{"label": "Ticket", "value": "no ticket found"}]}""");

        DeliveryEvaluator.Delivery onRead = evaluator.compare(read, read, "claim", "FAKE");
        DeliveryEvaluator.Delivery onExport = evaluator.compare(export, export, "claim", "FAKE");

        assertThat(onRead.notLookedUp()).isEqualTo("CLAIMED_TICKET");
        assertThat(onRead.passed()).as("nothing changed where nothing reads the claim").isTrue();
        assertThat(onExport.notLookedUp()).isNull();
        assertThat(onExport.passed()).as("an export reads the claim; an unchanged Ticket is not delivered").isFalse();
    }

    @Test
    void aSealThatDoesNotSayWhatWasLookedUpIsComparedAsBefore() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Subject", "value": "lab-adm-a"}]}""");

        DeliveryEvaluator.Delivery approval = evaluator.compare(base, base, "approval", "true");
        DeliveryEvaluator.Delivery claim = evaluator.compare(base, base, "claim", "FAKE");

        assertThat(base.checkedRecordKinds()).isNull();
        assertThat(base.actionFamily()).isNull();
        assertThat(approval.notLookedUp()).isNull();
        assertThat(approval.passed()).isFalse();
        assertThat(claim.notLookedUp()).isNull();
        assertThat(claim.passed()).isFalse();
    }

    @Test
    void thePolicyTheTargetAndTheRequestPathFollowTheEmployee() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Subject", "value": "lab-adm-a"},
                           {"label": "PolicySatisfied", "value": "no - not assigned to PRJ-ATLAS"},
                           {"label": "Target", "value": "Document ATL-DWG-00002 of project PRJ-ATLAS"},
                           {"label": "UntrustedText1", "value": "GET /api/documents/ATL-DWG-00002"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Subject", "value": "lab-eng-01"},
                           {"label": "PolicySatisfied", "value": "yes - assigned to HX-310"},
                           {"label": "Target", "value": "Document HX-310-DWG-00002 of project HX-310"},
                           {"label": "UntrustedText1", "value": "GET /api/documents/HX-310-DWG-00002"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "employee", "eng-01");

        assertThat(delivery.delivered()).containsExactly("Subject");
        assertThat(delivery.derived()).containsExactly("PolicySatisfied", "Target", "UntrustedText1");
        assertThat(delivery.unexpected()).isEmpty();
        assertThat(delivery.passed()).isTrue();
    }

    @Test
    void everyConditionOfTheApplicabilityTableSaysWhatItNeeds() throws Exception {
        JsonNode applies;
        try (var stream = DeliveryEvaluator.class.getResourceAsStream("/reactivity/delivery-expected.json")) {
            applies = JSON.readTree(stream).path("applies");
        }
        JsonNode conditions = applies.path("conditions");
        assertThat(applies.path("because").asText()).isNotBlank();
        assertThat(conditions.size()).isEqualTo(4);
        assertThat(conditions.path("approval").path("recordKind").asText()).isEqualTo("APPROVAL");
        assertThat(conditions.path("onCall").path("recordKind").asText()).isEqualTo("ON_CALL");
        assertThat(conditions.path("ticket").path("recordKind").asText()).isEqualTo("TICKET");
        assertThat(conditions.path("claim").path("actionFamilies").get(0).asText()).isEqualTo("EXPORT");
        assertThat(conditions.path("claim").path("lookup").asText()).isEqualTo("CLAIMED_TICKET");
    }

    @Test
    void aLaterStepMayChangeTheLinesThatFollowTheRunsEarlierSteps() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Time", "value": "14:21 Wed"},
                           {"label": "RequestsInSession", "value": "1 so far: 14:20 EXPORT -> ALLOW"},
                           {"label": "PeerReference", "value": "hour 14: 20% of the organization"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Time", "value": "03:18 Wed"},
                           {"label": "RequestsInSession", "value": "1 so far: 03:17 EXPORT -> ALLOW"},
                           {"label": "PeerReference", "value": "hour 14: 16% of the organization"}]}""");

        DeliveryEvaluator.Delivery second = evaluator.compare(base, variant, "timeSlot", "DAWN", 2);

        assertThat(second.delivered()).containsExactly("Time");
        assertThat(second.derived()).containsExactly("PeerReference", "RequestsInSession");
        assertThat(second.unexpected()).isEmpty();
        assertThat(second.valueMatches()).as("only the first step says the requested time").isNull();
        assertThat(second.passed()).isTrue();
    }

    @Test
    void theSameChangesOnTheFirstStepFail() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Time", "value": "14:20 Wed"},
                           {"label": "RequestsInSession", "value": "none so far"},
                           {"label": "PeerReference", "value": "hour 14: 20% of the organization"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Time", "value": "03:17 Wed"},
                           {"label": "RequestsInSession", "value": "1 so far: 03:16 READ -> ALLOW"},
                           {"label": "PeerReference", "value": "hour 14: 16% of the organization"}]}""");

        DeliveryEvaluator.Delivery first = evaluator.compare(base, variant, "timeSlot", "DAWN", 1);

        assertThat(first.valueMatches()).isTrue();
        assertThat(first.unexpected()).containsExactly("PeerReference", "RequestsInSession");
        assertThat(first.passed()).isFalse();
    }

    @Test
    void thePeerReferenceOfALaterStepFollowsOnlyTheTimeSlot() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Network", "value": "10.40.12.0/24 zone CORPORATE"},
                           {"label": "RequestsInSession", "value": "1 so far: 14:20 EXPORT -> ALLOW"},
                           {"label": "PeerReference", "value": "hour 14: 20% of the organization"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Network", "value": "203.0.113.0/24 zone EXTERNAL"},
                           {"label": "RequestsInSession", "value": "1 so far: 14:20 EXPORT -> CHALLENGE"},
                           {"label": "PeerReference", "value": "hour 14: 16% of the organization"}]}""");

        DeliveryEvaluator.Delivery second = evaluator.compare(base, variant, "place", "EXTERNAL", 2);

        assertThat(second.derived()).containsExactly("RequestsInSession");
        assertThat(second.unexpected()).containsExactly("PeerReference");
        assertThat(second.passed()).isFalse();
    }

    @Test
    void onlyTheFirstStepMustDeliverAnExpectedFact() throws Exception {
        PromptFacts step = facts("""
                {"lines": [{"label": "Target", "value": "Document HX-310-DWG-00002 of project HX-310"}]}""");

        DeliveryEvaluator.Delivery second = evaluator.compare(step, step, "items", "40", 2);
        DeliveryEvaluator.Delivery first = evaluator.compare(step, step, "items", "40", 1);

        assertThat(second.passed()).as("the item count is the first step's").isTrue();
        assertThat(first.passed()).isFalse();
    }

    @Test
    void everyLaterStepFactOfTheResourceHasItsReason() throws Exception {
        JsonNode laterSteps;
        try (var stream = DeliveryEvaluator.class.getResourceAsStream("/reactivity/delivery-expected.json")) {
            laterSteps = JSON.readTree(stream).path("laterSteps");
        }
        assertThat(laterSteps.size()).isEqualTo(2);
        assertThat(laterSteps.path("*").path("facts").path(0).asText()).isEqualTo("RequestsInSession");
        assertThat(laterSteps.path("timeSlot").path("facts").path(0).asText()).isEqualTo("PeerReference");
        laterSteps.fields().forEachRemaining(condition ->
                assertThat(condition.getValue().path("because").asText()).as(condition.getKey()).isNotBlank());
    }

    @Test
    void theOnCallRosterFollowsTheEmployee() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Subject", "value": "lab-eng-k"},
                           {"label": "OnCall", "value": "on call (HX on-call)"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Subject", "value": "lab-eng-01"},
                           {"label": "OnCall", "value": "not on call"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "employee", "eng-01");

        assertThat(delivery.derived()).containsExactly("OnCall");
        assertThat(delivery.unexpected()).isEmpty();
        assertThat(delivery.passed()).isTrue();
    }

    @Test
    void theRelativeEndsOfOnCallAndOfATicketFollowTheTimeSlot() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Time", "value": "14:20 Wed"},
                           {"label": "OnCall", "value": "on call until 10-05 09:00 (4 days after)"},
                           {"label": "Ticket", "value": "INC-7 valid until 10-05 09:00 (4 days after)"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Time", "value": "03:17 Wed"},
                           {"label": "OnCall", "value": "on call until 10-05 09:00 (5 days after)"},
                           {"label": "Ticket", "value": "INC-7 valid until 10-05 09:00 (5 days after)"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "timeSlot", "DAWN");

        assertThat(delivery.delivered()).containsExactly("Time");
        assertThat(delivery.derived()).containsExactly("OnCall", "Ticket");
        assertThat(delivery.unexpected()).isEmpty();
        assertThat(delivery.passed()).isTrue();
    }

    @Test
    void aConditionTheBaseAlreadyHadIsTheBaseItself() throws Exception {
        PromptFacts onCall = facts("""
                {"lines": [{"label": "OnCall", "value": "on call (HX on-call)"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(onCall, onCall, "onCall", "true");

        assertThat(delivery.changed()).isEmpty();
        assertThat(delivery.valueMatches()).as("the variant states the value").isTrue();
        assertThat(delivery.sameAsBase()).isTrue();
        assertThat(delivery.passed()).isTrue();
    }

    @Test
    void aConditionThatChangedNothingAndDoesNotStateItsValueStillFails() throws Exception {
        PromptFacts notOnCall = facts("""
                {"lines": [{"label": "OnCall", "value": "not on call"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(notOnCall, notOnCall, "onCall", "true");

        assertThat(delivery.valueMatches()).isFalse();
        assertThat(delivery.sameAsBase()).isFalse();
        assertThat(delivery.passed()).isFalse();
    }

    @Test
    void theResourceGivesTheOnCallRosterAndTheRelativeEndsTheirConditions() throws Exception {
        JsonNode derived;
        try (var stream = DeliveryEvaluator.class.getResourceAsStream("/reactivity/delivery-expected.json")) {
            derived = JSON.readTree(stream).path("derived");
        }
        assertThat(derived.path("employee").path("facts")).extracting(JsonNode::asText).contains("OnCall");
        assertThat(derived.path("employee").path("because").asText()).contains("on-call roster");
        assertThat(derived.path("timeSlot").path("facts")).extracting(JsonNode::asText).contains("OnCall", "Ticket");
        assertThat(derived.path("timeSlot").path("because").asText()).contains("ticket's validity");
        assertThat(derived.path("target").path("facts")).extracting(JsonNode::asText).contains("Ticket");
        assertThat(derived.path("target").path("because").asText()).contains("a ticket names its project");
        assertThat(derived.path("onCall").path("facts")).extracting(JsonNode::asText)
                .containsExactly("DeviationsFromBaseline");
        assertThat(derived.path("onCall").path("because").asText()).contains("ticket while on call");
    }

    @Test
    void aTicketFollowsTheTargetLikeTheApproval() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "Assignment", "value": "not assigned to GB-500"},
                           {"label": "Ticket", "value": "TCK-1 by pm-11 for GB-500 covers this request"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Assignment", "value": "assigned to PLM-OPS"},
                           {"label": "Ticket", "value": "TCK-1 by adm-a for PLM-OPS does not cover"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "target", "ASSIGNED");

        assertThat(delivery.delivered()).containsExactly("Assignment");
        assertThat(delivery.derived()).containsExactly("Ticket");
        assertThat(delivery.unexpected()).isEmpty();
        assertThat(delivery.passed()).isTrue();
    }

    @Test
    void theDeviationsFollowOnCallThroughThePolicysTicketException() throws Exception {
        PromptFacts base = facts("""
                {"lines": [{"label": "OnCall", "value": "on call (PLATFORM)"},
                           {"label": "PolicySatisfied", "value": "yes - ticket while on call"},
                           {"label": "DeviationsFromBaseline", "value": "1 of 8 -> time 20 explained by TCK-1"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "OnCall", "value": "not on call"},
                           {"label": "PolicySatisfied", "value": "no - no approval"},
                           {"label": "DeviationsFromBaseline", "value": "1 of 8 -> time 20 (unexplained)"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "onCall", "false");

        assertThat(delivery.delivered()).containsExactly("OnCall", "PolicySatisfied");
        assertThat(delivery.derived()).containsExactly("DeviationsFromBaseline");
        assertThat(delivery.passed()).isTrue();
    }

    private static PromptFacts facts(String json) throws Exception {
        JsonNode node = JSON.readTree(json);
        return PromptFacts.of(node);
    }
}
