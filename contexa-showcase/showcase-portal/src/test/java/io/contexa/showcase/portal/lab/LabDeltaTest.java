package io.contexa.showcase.portal.lab;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.reactivity.DeliveryEvaluator;
import io.contexa.showcase.portal.reactivity.ReactivityService;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W7-13 (docs/showcase/화면설계-프롬프트신뢰-보강안.md 3.4, 5): the lab result's delta. Only a composition with exactly one
 * changed condition has one; the harness's delivery check of the visitor's run against the designed run gives the
 * changed lines, those the condition should change and those it should not; the values before and after are the
 * sealed prompts' lines, HTTP session identifiers masked.
 */
class LabDeltaTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void onlyACompletedRunWithOneChangedConditionIsCompared() {
        assertThat(LabDelta.refusal(composition(List.of(), "COMPLETED"))).isEqualTo("DESIGNED");
        assertThat(LabDelta.refusal(composition(List.of("approval", "items"), "COMPLETED")))
                .isEqualTo("SEVERAL_CONDITIONS");
        assertThat(LabDelta.refusal(composition(List.of("approval"), "RUNNING"))).isEqualTo("NOT_COMPLETED");
        assertThat(LabDelta.refusal(composition(List.of("approval"), "COMPLETED"))).isNull();
    }

    @Test
    void theConditionAndItsValueAreTheStoredOnes() {
        assertThat(LabDelta.condition(composition(List.of("items"), "COMPLETED"))).isEqualTo("items");
        assertThat(LabDelta.value(composition(List.of("items"), "COMPLETED"))).isEqualTo("4831");
        assertThat(LabDelta.value(composition(List.of("approval"), "COMPLETED"))).isEqualTo("true");
        assertThat(LabDelta.value(composition(List.of("timeSlot"), "COMPLETED"))).isEqualTo("AFTERNOON");

        LabDelta several = LabDelta.without(composition(List.of("approval", "items"), "COMPLETED"), null,
                LabDelta.SEVERAL_CONDITIONS);
        assertThat(several.available()).isFalse();
        assertThat(several.condition()).isNull();
        assertThat(several.steps()).isEmpty();
    }

    @Test
    void theChangedLinesComeWithTheirValuesBeforeAndAfter() throws Exception {
        Map<String, JsonNode> facts = new HashMap<>();
        facts.put("req-base", JSON.readTree("""
                {"lines": [{"label": "PolicySatisfied", "value": "no - no approval for GB-500"},
                           {"label": "Approval", "value": "none found"},
                           {"label": "Time", "value": "Wed 03:17"}]}"""));
        facts.put("req-lab", JSON.readTree("""
                {"lines": [{"label": "PolicySatisfied", "value": "yes - approval APR-1"},
                           {"label": "Approval", "value": "APR-1 by pm-11 - covers this request"},
                           {"label": "Time", "value": "Wed 03:17"},
                           {"label": "Session", "value": "0123456789ABCDEF0123456789ABCDEF"}]}"""));
        ReactivityService.RunDelivery delivery = new ReactivityService.RunDelivery("run-base00000000",
                "run-lab000000000", "approval", "true", List.of(
                new ReactivityService.StepDelivery(1, "req-base", "req-lab", new DeliveryEvaluator.Delivery(
                        List.of("Approval", "PolicySatisfied", "Session"), List.of("Approval", "PolicySatisfied"),
                        List.of("Session"), true, false, 2), null),
                new ReactivityService.StepDelivery(2, "req-base-2", null, null, "NO_VARIANT_STEP")), false);

        LabDelta delta = LabDelta.of(composition(List.of("approval"), "COMPLETED"), delivery, facts);

        assertThat(delta.available()).isTrue();
        assertThat(delta.baseRunId()).isEqualTo("run-base00000000");
        assertThat(delta.condition()).isEqualTo("approval");
        assertThat(delta.value()).isEqualTo("true");
        assertThat(delta.steps()).hasSize(2);
        LabDelta.Step first = delta.steps().get(0);
        assertThat(first.changed()).containsExactly(
                new LabDelta.Change("Approval", List.of("none found"), List.of("APR-1 by pm-11 - covers this request")),
                new LabDelta.Change("PolicySatisfied", List.of("no - no approval for GB-500"),
                        List.of("yes - approval APR-1")),
                new LabDelta.Change("Session", List.of(), List.of("<SESSION>")));
        assertThat(first.expected()).containsExactly("Approval", "PolicySatisfied");
        assertThat(first.unexpected()).as("a line the condition should not change").containsExactly("Session");
        assertThat(first.valueMatches()).isTrue();
        assertThat(first.passed()).isFalse();
        assertThat(first.notCompared()).isNull();
        assertThat(first.unchangedLines()).as("as the delivery check counted them").isEqualTo(2);
        LabDelta.Step second = delta.steps().get(1);
        assertThat(second.notCompared()).isEqualTo("NO_VARIANT_STEP");
        assertThat(second.changed()).isEmpty();
        assertThat(second.passed()).isFalse();
        assertThat(second.unchangedLines()).as("not compared").isNull();
    }

    @Test
    void theDeltaHasTheContractsFields() throws Exception {
        ReactivityService.RunDelivery delivery = new ReactivityService.RunDelivery("run-base00000000",
                "run-lab000000000", "approval", "true", List.of(new ReactivityService.StepDelivery(1, "a", "b",
                new DeliveryEvaluator.Delivery(List.of("Approval"), List.of("Approval"), List.of(), true, true, 5),
                null)), true);
        Map<String, JsonNode> facts = new HashMap<>();
        facts.put("a", JSON.readTree("{\"lines\": [{\"label\": \"Approval\", \"value\": \"none found\"}]}"));
        facts.put("b", JSON.readTree("{\"lines\": [{\"label\": \"Approval\", \"value\": \"APR-1\"}]}"));

        JsonNode delta = JSON.valueToTree(LabDelta.of(composition(List.of("approval"), "COMPLETED"), delivery, facts));

        assertThat(names(delta)).containsExactlyInAnyOrder("runId", "baseRunId", "condition", "value", "available",
                "reason", "steps");
        assertThat(names(delta.path("steps").path(0))).containsExactlyInAnyOrder("stepNo", "changed", "expected",
                "unexpected", "valueMatches", "passed", "notCompared", "unchangedLines");
        assertThat(names(delta.path("steps").path(0).path("changed").path(0))).containsExactlyInAnyOrder("label",
                "before", "after");
    }

    private static LabStore.Composition composition(List<String> changed, String status) {
        Map<String, Object> conditions = new HashMap<>();
        conditions.put("employee", "adm-a");
        conditions.put("timeSlot", "AFTERNOON");
        conditions.put("items", 4831);
        conditions.put("approval", true);
        return new LabStore.Composition("run-lab000000000", "A3", changed.isEmpty(), changed, conditions,
                Instant.parse("2026-10-16T03:00:00Z"), status, "f".repeat(64), null, null);
    }

    private static List<String> names(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }
}
