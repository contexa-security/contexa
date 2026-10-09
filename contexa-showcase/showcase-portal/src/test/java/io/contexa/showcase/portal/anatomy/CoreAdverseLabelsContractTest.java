package io.contexa.showcase.portal.anatomy;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W1-4c: the adverse labels the anatomy shows are exactly the labels of the core's response inspector, read from the
 * core source in this repository. When the core changes its rule, this test fails instead of the demo drifting.
 */
class CoreAdverseLabelsContractTest {

    private static final Path INSPECTOR = Path.of("..", "..", "contexa-core", "src", "main", "java", "io", "contexa",
            "contexacore", "std", "pipeline", "processor", "SecurityDecisionRawOutputContractInspector.java");

    @Test
    void theLabelsAreTheCoreInspectorsExplicitAdverseEvidenceRule() throws IOException {
        String source = Files.readString(INSPECTOR, StandardCharsets.UTF_8);
        int start = source.indexOf("boolean explicitAdverseEvidence");
        int end = source.indexOf("if (authorizationAllows", start);
        assertThat(start).as("the rule is still where the demo reads it").isPositive();
        String rule = source.substring(start, end);

        Map<String, String> core = new HashMap<>();
        Matcher any = Pattern.compile("hasAnyPromptFact\\(promptText, \"([a-z]+)\", \"(true|false)\"\\)").matcher(rule);
        while (any.find()) {
            core.put(any.group(1), any.group(2).toUpperCase());
        }
        Matcher count = Pattern.compile("positiveCount\\(promptFactValue\\(promptText, \"([a-z]+)\"\\)\\)").matcher(rule);
        while (count.find()) {
            core.put(count.group(1), "POSITIVE");
        }
        assertThat(rule).contains("anomalySignal != null").contains("\"none\".equals(anomalySignal)")
                .contains("\"unknown\".equals(anomalySignal)");
        core.put("observedanomalysignal", "SIGNAL");
        assertThat(source).contains("String anomalySignal = promptFactValue(promptText, \"observedanomalysignal\")");
        assertThat(source).contains("\"deny\".equals(authorizationEffect)").contains("\"block\".equals(authorizationEffect)")
                .contains("String authorizationEffect = promptFactValue(promptText, \"authorizationeffect\")");
        core.put("authorizationeffect", "DENY_OR_BLOCK");

        Map<String, String> demo = new HashMap<>();
        CoreAdverseLabels.RULES.forEach(entry -> demo.put(entry.key(), entry.condition()));
        assertThat(demo).isEqualTo(core);
    }

    @Test
    void valuesAreReadTheWayTheInspectorReadsThem() {
        String prompt = """
                System rules mention ApprovalMissing=true only inside a sentence.
                ApprovalMissing: true
                RoleScopeDeltaCount: UNKNOWN
                RecentBlockCount: 2 blocks
                ObservedAnomalySignal: none
                CurrentActionFamilyPresentInExpectedRoleScope: true
                """;
        Map<String, CoreAdverseLabels.Reading> read = new HashMap<>();
        CoreAdverseLabels.read(prompt).forEach(reading -> read.put(reading.label(), reading));

        assertThat(read.get("approvalmissing").values()).containsExactly("true");
        assertThat(read.get("approvalmissing").met()).isTrue();
        assertThat(read.get("rolescopedeltacount").met()).as("UNKNOWN is not a count").isFalse();
        assertThat(read.get("recentblockcount").met()).isTrue();
        assertThat(read.get("observedanomalysignal").met()).isFalse();
        assertThat(read.get("currentactionfamilypresentinexpectedrolescope").met()).isFalse();
        assertThat(read.get("impossibletravel").values()).as("not in the prompt").isEqualTo(List.of());
        assertThat(CoreAdverseLabels.read(null)).isEmpty();
    }
}
