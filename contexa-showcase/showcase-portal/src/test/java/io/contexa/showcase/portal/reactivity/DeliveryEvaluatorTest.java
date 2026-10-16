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
                {"lines": [{"label": "Time", "value": "03:17 Wed"}, {"label": "OnCall", "value": "not on call"}]}""");
        PromptFacts variant = facts("""
                {"lines": [{"label": "Time", "value": "14:05 Wed"}, {"label": "OnCall", "value": "on call (HX)"}]}""");

        DeliveryEvaluator.Delivery delivery = evaluator.compare(base, variant, "timeSlot");

        assertThat(delivery.unexpected()).containsExactly("OnCall");
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

    private static PromptFacts facts(String json) throws Exception {
        JsonNode node = JSON.readTree(json);
        return PromptFacts.of(node);
    }
}
