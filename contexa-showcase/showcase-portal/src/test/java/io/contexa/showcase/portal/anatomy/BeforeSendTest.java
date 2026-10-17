package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The "usual" column of the comparison before sending is what the engine's prompt listed for each dimension (work 8
 * of docs/showcase/화면설계서-v2-구현계획.md). The prompt below is a real decision of the 2026-10-06 measurement.
 * N-K5-1: a v20 system text states the minimum action rules, read with the engine's findings of real v20.23 decisions.
 */
class BeforeSendTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void theUsualValuesAreCopiedFromThePromptLinesOfEachDimension() throws Exception {
        Map<String, BeforeSend.Usual> usual = BeforeSend.usual(userPrompt("a3s-challenge"));

        assertThat(usual).containsOnlyKeys("accessHour", "dayOfWeek", "network", "browser", "operatingSystem",
                "authenticationType", "pathFamily", "actionFamily", "resourceFamily");
        assertThat(usual.get("accessHour")).isEqualTo(new BeforeSend.Usual("ObservedHours",
                List.of("10", "14", "15", "16", "17", "11", "12", "13", "9")));
        assertThat(usual.get("dayOfWeek").values()).containsExactly("3", "4", "5", "1", "2");
        assertThat(usual.get("browser").values()).containsExactly("Chrome/140");
        assertThat(usual.get("actionFamily").values()).containsExactly("READ", "WRITE");
        assertThat(usual.get("resourceFamily").values()).containsExactly("NORMAL");
        assertThat(usual.get("pathFamily").label()).as("the prompt lists the most frequent paths").isEqualTo(
                "FrequentPaths");
        assertThat(usual.get("pathFamily").values()).contains("/api/projects/PLM-OPS/exports/*");
    }

    @Test
    void onlyCompanyRecordLabelsTheInspectorReadAsAdverseAreFlagged() {
        List<CoreAdverseLabels.Reading> readings = List.of(
                new CoreAdverseLabels.Reading("approvalrequired", "TRUE", List.of("true"), true),
                new CoreAdverseLabels.Reading("approvalmissing", "TRUE", List.of("false"), false),
                new CoreAdverseLabels.Reading("failedloginattempts", "POSITIVE", List.of("3"), true));

        assertThat(BeforeSend.companyAdverse(readings)).extracting(CoreAdverseLabels.Reading::label)
                .as("an approval on file still leaves the requirement read as adverse; sign-in failures are not company "
                        + "records").containsExactly("approvalrequired");
        assertThat(BeforeSend.companyAdverse(null)).isEmpty();
    }

    @Test
    void theHardLineAppliesOnlyWhenAllFourConditionsOfTheJudgmentRulesHold() throws Exception {
        String prompt = userPrompt("a3s-challenge");
        List<CoreAdverseLabels.Reading> missing = List.of(
                new CoreAdverseLabels.Reading("approvalmissing", "TRUE", List.of("true"), true));
        List<CoreAdverseLabels.Reading> onFile = List.of(
                new CoreAdverseLabels.Reading("approvalmissing", "TRUE", List.of("false"), false));

        BeforeSend.Boundary attack = BeforeSend.boundary(prompt, "CRITICAL", 3, missing);
        assertThat(attack.established()).as("the measured prompt renders an established personal baseline").isTrue();
        assertThat(attack.applies()).isTrue();
        assertThat(BeforeSend.boundary(prompt, "CRITICAL", 3, onFile).applies())
                .as("an approval on file takes the request out of the boundary").isFalse();
        assertThat(BeforeSend.boundary(prompt, "NORMAL", 3, missing).applies()).isFalse();
        assertThat(BeforeSend.boundary(prompt, "HIGH", 0, missing).applies()).isFalse();
        assertThat(BeforeSend.boundary(null, "CRITICAL", 3, missing).applies())
                .as("without the prompt text the baseline state is unknown").isNull();
    }

    /**
     * N-DEP-1 (W7-12 C-2, C-5): the "usual" of a v20 step (E1-2) is the BaselineView the engine sealed with it, the
     * computation its USER BASELINE lines are drawn from, one value per item so the screen names each in plain words:
     * step 1 of the A3 run of anatomy/v20-deviations.json.
     */
    @Test
    void theUsualOfAV20StepIsTheBaselineViewTheEngineSealed() throws Exception {
        JsonNode attack = resource("v20-deviations").path("decisions").get(0);
        JsonNode metadata = JSON.readTree(attack.path("records").get(0).path("metadataJson").asText());
        Map<String, Object> workProfile = JSON.convertValue(
                metadata.path("sealedEvidence.canonicalContext").path("workProfile"), new TypeReference<>() {
                });

        Map<String, BeforeSend.Usual> usual = BeforeSend.sealedUsual(workProfile);

        assertThat(attack.path("case").asText()).isEqualTo("A3");
        assertThat(usual).containsOnlyKeys("accessHour", "dayOfWeek", "network", "device", "authenticationType",
                "target", "actionFamily", "resourceFamily", "size", "rate");
        assertThat(usual.get("accessHour")).isEqualTo(new BeforeSend.Usual("UsualHours",
                List.of("10", "11", "13", "14", "17")));
        assertThat(usual.get("dayOfWeek").values()).containsExactly("1", "2", "3", "4", "5");
        assertThat(usual.get("device").values()).containsExactly("Chrome/140 on WINDOWS");
        assertThat(usual.get("authenticationType").values()).containsExactly("PASSWORD", "PASSWORD+ONE_TIME_CODE");
        assertThat(usual.get("target").values()).containsExactly("projectKey=PLM-OPS");
        assertThat(usual.get("actionFamily").values()).containsExactly("READ", "EXPORT");
        assertThat(usual.get("resourceFamily").values()).as("the class of NORMAL=24").containsExactly("NORMAL");
        assertThat(usual.get("size")).as("the largest export").isEqualTo(new BeforeSend.Usual("UsualExportSize",
                List.of("29")));
        assertThat(usual.get("rate")).as("the median per active hour").isEqualTo(new BeforeSend.Usual(
                "UsualRequestRate", List.of("1")));
        assertThat(BeforeSend.sealedUsual(Map.of())).as("a decision without a sealed view").isEmpty();
    }

    @Test
    void aMissingLineIsLeftOut() {
        assertThat(BeforeSend.usual("ObservedHours: 9, 10\nObservedDays:\n")).containsOnlyKeys("accessHour");
    }

    @Test
    void theMinimumActionRulesOfAV20TextComeWithTheEnginesFindings() throws Exception {
        JsonNode fixture = resource("v20-minimum-rules");
        String system = fixture.path("systemPrompt").asText();

        BeforeSend.MinimumRules escalated = BeforeSend.minimumRules(system, records(fixture, 0));
        BeforeSend.MinimumRules challenged = BeforeSend.minimumRules(system, records(fixture, 1));
        BeforeSend.MinimumRules allowed = BeforeSend.minimumRules(system, records(fixture, 2));

        assertThat(escalated).as("the v20.23 text states the minimum action rules").isNotNull();
        assertThat(challenged).isNotNull();
        assertThat(allowed).isNotNull();
        assertThat(escalated.rules()).extracting(BeforeSend.MinimumRule::code).containsExactly(
                "MIN_P1_IDENTITY_DEVIATION", "MIN_P2_NEW_DEVICE_OR_NETWORK_EXPORT", "MIN_P3_POLICY_NOT_SATISFIED");
        assertThat(escalated.rules()).extracting(BeforeSend.MinimumRule::floor)
                .containsExactly("CHALLENGE", "CHALLENGE", "ESCALATE");
        assertThat(escalated.rules()).extracting(BeforeSend.MinimumRule::line).as("each rule's line as sent")
                .allSatisfy(line -> assertThat(system.lines().toList()).contains(line));
        assertThat(escalated.rules()).extracting(BeforeSend.MinimumRule::met).containsExactly(false, false, true);
        assertThat(escalated.applies()).isTrue();
        assertThat(challenged.rules()).extracting(BeforeSend.MinimumRule::met).containsExactly(true, true, false);
        assertThat(challenged.applies()).isTrue();
        assertThat(allowed.rules()).extracting(BeforeSend.MinimumRule::met).containsExactly(false, false, false);
        assertThat(allowed.applies()).as("the engine found no rule met").isFalse();
    }

    @Test
    void withoutTheStepsDecisionRecordEveryRuleIsUnknown() throws Exception {
        String system = resource("v20-minimum-rules").path("systemPrompt").asText();

        for (String records : new String[] {null, "null", "[]"}) {
            BeforeSend.MinimumRules rules = BeforeSend.minimumRules(system, records);
            assertThat(rules).as(String.valueOf(records)).isNotNull();
            assertThat(rules.rules()).extracting(BeforeSend.MinimumRule::met).containsOnlyNulls();
            assertThat(rules.applies()).isNull();
        }
    }

    @Test
    void aFindingIsReadFromMetadataStoredAsAnObjectToo() throws Exception {
        String system = resource("v20-minimum-rules").path("systemPrompt").asText();

        BeforeSend.MinimumRules rules = BeforeSend.minimumRules(system, """
                [{"success": true, "metadataJson": {"minimumActionMode": "ENFORCE", "minimumActionFindings": [
                  {"rule": "P2_NEW_DEVICE_OR_NETWORK_EXPORT", "code": "MIN_P2_NEW_DEVICE_OR_NETWORK_EXPORT",
                   "requiredAction": "CHALLENGE", "dimensions": ["NETWORK"]}]}}]""");

        assertThat(rules).isNotNull();
        assertThat(rules.rules()).extracting(BeforeSend.MinimumRule::met).containsExactly(false, true, false);
    }

    @Test
    void aV2015TextNamesTheFloorInItsHeadOnly() throws Exception {
        BeforeSend.MinimumRules rules = BeforeSend.minimumRules("""
                Minimum action rules (a floor: when a rule applies, choose CHALLENGE or a stronger action; a rule is no reason to choose an action stronger than CHALLENGE):
                P1 MIN_P1_IDENTITY_DEVIATION: ResourceClass is SENSITIVE or CRITICAL and DeviationsFromBaseline names at least 2 of time, day, network and device as unexplained.
                P3 MIN_P3_POLICY_NOT_SATISFIED: PolicySatisfied is no.
                A difference explained by a record, against a baseline that is not established, or not compared is not unexplained.
                """, """
                [{"success": true, "metadataJson": "{}"}]""");

        assertThat(rules).isNotNull();
        assertThat(rules.rules()).extracting(BeforeSend.MinimumRule::code)
                .containsExactly("MIN_P1_IDENTITY_DEVIATION", "MIN_P3_POLICY_NOT_SATISFIED");
        assertThat(rules.rules()).extracting(BeforeSend.MinimumRule::floor).containsOnlyNulls();
        assertThat(rules.applies()).as("a record without findings: no rule met").isFalse();
    }

    @Test
    void aTextThatStatesNoMinimumActionRuleHasNone() throws Exception {
        assertThat(BeforeSend.minimumRules(systemPrompt("a3s-challenge"), "[]"))
                .as("a v19 text states the elevated-risk boundary instead").isNull();
        assertThat(BeforeSend.minimumRules(null, "[]")).isNull();
    }

    private static JsonNode resource(String name) throws Exception {
        try (InputStream in = BeforeSendTest.class.getResourceAsStream("/anatomy/" + name + ".json")) {
            return JSON.readTree(in);
        }
    }

    private static String records(JsonNode fixture, int decision) {
        return fixture.path("decisions").get(decision).path("records").toString();
    }

    private static String systemPrompt(String name) throws Exception {
        return resource(name).path("exchanges").get(0).path("systemPrompt").asText();
    }

    private static String userPrompt(String name) throws Exception {
        try (InputStream in = BeforeSendTest.class.getResourceAsStream("/anatomy/" + name + ".json")) {
            JsonNode record = JSON.readTree(in);
            return record.path("exchanges").get(0).path("userPrompt").asText();
        }
    }
}
