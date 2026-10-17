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
    private static final Path FACT_CHECKS = Path.of("..", "..", "contexa-core", "src", "main", "java", "io", "contexa",
            "contexacore", "autonomous", "tiered", "prompt", "SecurityDecisionFactChecks.java");

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
        Matcher stated = Pattern.compile("statedFact\\(promptFactValue\\(promptText, \"([a-z]+)\"\\)\\)").matcher(rule);
        while (stated.find()) {
            core.put(stated.group(1), "STATED");
        }
        assertThat(rule).contains("anomalySignal != null").contains("\"none\".equals(anomalySignal)")
                .contains("\"unknown\".equals(anomalySignal)")
                .contains("anomalyTrust.startsWith(\"trusted_verification_input\")");
        assertThat(source).contains("String anomalyTrust = promptFactValue(promptText, \"anomalysignaltrust\")");
        core.put("observedanomalysignal", "TRUSTED_SIGNAL");
        assertThat(source).contains("String anomalySignal = promptFactValue(promptText, \"observedanomalysignal\")");
        assertThat(source).contains("\"deny\".equals(authorizationEffect)").contains("\"block\".equals(authorizationEffect)")
                .contains("String authorizationEffect = promptFactValue(promptText, \"authorizationeffect\")");
        core.put("authorizationeffect", "DENY_OR_BLOCK");

        Map<String, String> demo = new HashMap<>();
        CoreAdverseLabels.RULES.forEach(entry -> demo.put(entry.key(), entry.condition()));
        assertThat(demo).isEqualTo(core);
    }

    /**
     * N-DEP-2: the adverse conditions of a v20 decision are the core's v20 inspection's (SecurityDecisionFactChecks) as
     * far as the facts the engine sealed state them; the test reads the core's list from its source and fails when the
     * list changes, so the demo is looked at again instead of drifting.
     */
    @Test
    void theSealedConditionsAreTheCoreV20InspectionsAdverseFacts() throws IOException {
        String source = Files.readString(FACT_CHECKS, StandardCharsets.UTF_8).replaceAll("\\s+", " ");
        int start = source.indexOf("boolean adverseOtherThanTheDifferences() {");
        assertThat(start).as("the list is still where the demo reads it").isPositive();
        int returns = source.indexOf("return ", start) + "return ".length();
        List<String> terms = List.of(source.substring(returns, source.indexOf("; }", returns)).split(" \\|\\| "));

        assertThat(terms).as("the core's adverse facts, in its order").containsExactly(
                "\"BLOCK\".equals(effect)", "\"DENY\".equals(effect)", "fact(\"SessionDeviceChange\").isPresent()",
                "fact(\"SessionNetworkChange\").isPresent()", "anySignal(intent())", "impossibleTravel()",
                "(factHas(\"RoleScope\", \"ROLE_SCOPE_OUTSIDE\") && !provisionalScope)",
                "fact(\"DataConflicts\").isPresent()", "prompt.states(PromptBlock.DECISION_FACTS, \"BlockedUser\")",
                "prompt.states(PromptBlock.SESSION, \"RecentDenied\")",
                "prompt.states(PromptBlock.DECISION_FACTS, \"ThreatMatch\")",
                "(session != null && prompt.states(PromptBlock.SESSION, \"FailedLogins\")"
                        + " && atLeast(session.getFailedLoginAttempts(), 1))",
                "(session != null && prompt.states(PromptBlock.SESSION, \"MfaFailures\")"
                        + " && atLeast(session.getRecentMfaFailureCount(), 1))");
        assertThat(source).contains("boolean unmetRequirement() { return prompt.states(PromptBlock.DECISION_FACTS,"
                + " \"Policy\") && !Boolean.TRUE.equals(policySatisfied()); }");

        Map<String, String> demo = new HashMap<>();
        CoreAdverseLabels.SEALED_RULES.forEach(entry -> demo.put(entry.key(), entry.condition()));
        assertThat(demo).as("the effect, the session changes, the data conflicts, the blocked user and the policy")
                .isEqualTo(Map.of("authorizationeffect", "DENY_OR_BLOCK", "sessiondevicechange", "STATED",
                        "sessionnetworkchange", "STATED", "dataconflicts", "STATED", "blockeduser", "STATED",
                        "policysatisfied", "NOT_SATISFIED"));
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
                SessionDeviceChange: Chrome/140 on WINDOWS -> Safari/17 on MAC in the same session
                SessionNetworkChange: UNKNOWN
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
        assertThat(read.get("sessiondevicechange").met()).as("a stated change").isTrue();
        assertThat(read.get("sessionnetworkchange").met()).as("UNKNOWN states no change").isFalse();
        assertThat(CoreAdverseLabels.read(null)).isEmpty();
    }

    @Test
    void onlyATrustedAnomalySignalIsAdverseEvidence() {
        String untrusted = "ObservedAnomalySignal: CLIENT_SUPPLIED_TEXT\nAnomalySignalTrust: UNTRUSTED_REQUEST_HEADER\n";
        String trusted = "ObservedAnomalySignal: CONFIRMED_CREDENTIAL_EXFILTRATION\nAnomalySignalTrust: TRUSTED_VERIFICATION_INPUT\n";

        assertThat(anomalyReading(untrusted).met()).isFalse();
        assertThat(anomalyReading(trusted).met()).isTrue();
    }

    private static CoreAdverseLabels.Reading anomalyReading(String prompt) {
        return CoreAdverseLabels.read(prompt).stream()
                .filter(reading -> "observedanomalysignal".equals(reading.label()))
                .findFirst().orElseThrow();
    }
}
