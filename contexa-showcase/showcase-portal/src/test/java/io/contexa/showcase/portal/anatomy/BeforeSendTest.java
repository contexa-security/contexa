package io.contexa.showcase.portal.anatomy;

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

    @Test
    void aMissingLineIsLeftOut() {
        assertThat(BeforeSend.usual("ObservedHours: 9, 10\nObservedDays:\n")).containsOnlyKeys("accessHour");
    }

    private static String userPrompt(String name) throws Exception {
        try (InputStream in = BeforeSendTest.class.getResourceAsStream("/anatomy/" + name + ".json")) {
            JsonNode record = JSON.readTree(in);
            return record.path("exchanges").get(0).path("userPrompt").asText();
        }
    }
}
