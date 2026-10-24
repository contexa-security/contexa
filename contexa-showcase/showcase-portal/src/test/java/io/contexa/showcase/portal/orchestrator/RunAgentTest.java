package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.run.RunFacts;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints.Control;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * docs/agent A7-0: a case can name the run's agent and, step by step, who sends to control D; the rule controls keep
 * receiving every step from the person's session, and the cases written before agents keep their definitions.
 */
class RunAgentTest {

    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();
    private final ScenarioDefinition.Agent reportAgent = new ScenarioDefinition.Agent("report",
            Map.of("en", "Report agent", "ko", "보고서 에이전트"), "ENGINEER", "10.60.1.0/24", "report-agent/1.0");

    @Test
    void controlDReceivesAnAgentsStepFromTheAgentAndTheRuleControlsFromThePerson() {
        Map<Control, ControlSession> people = new EnumMap<>(Control.class);
        for (Control control : Control.values()) {
            people.put(control, mock(ControlSession.class));
        }
        ControlSession delegatedAgent = mock(ControlSession.class);
        Map<ScenarioDefinition.Sender, ControlSession> agents = Map.of(
                ScenarioDefinition.Sender.DELEGATED_AGENT, delegatedAgent);

        assertThat(RunOrchestrator.sessionsOf(step(null), people, agents)).isSameAs(people);
        Map<Control, ControlSession> agentStep = RunOrchestrator.sessionsOf(
                step(ScenarioDefinition.Sender.DELEGATED_AGENT), people, agents);
        assertThat(agentStep.get(Control.D)).isSameAs(delegatedAgent);
        for (Control control : Control.values()) {
            if (control != Control.D) {
                assertThat(agentStep.get(control)).isSameAs(people.get(control));
            }
        }
        assertThatThrownBy(() -> RunOrchestrator.sessionsOf(step(ScenarioDefinition.Sender.AUTONOMOUS_AGENT), people,
                agents)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aDelegationFactIsTheRunsDelegationToItsAgent() {
        ScenarioDefinition.Fact fact = new ScenarioDefinition.Fact("DELEGATION", null, null, "HX-310", "REPORTING",
                null, Duration.ofHours(-1), Duration.ofHours(3), "ACTIVE", null, null, null, null, null, null,
                new ScenarioDefinition.Delegated(Map.of("en", "Prepare the weekly HX-310 report", "ko", "주간 보고서"),
                        List.of("DOCUMENT_READ"), List.of("HX-310"), false));
        Instant time = Instant.parse("2026-09-30T14:00:00Z");

        RunFacts facts = RunOrchestrator.facts(scenario(List.of(fact), reportAgent), "aabbccddeeff", time);

        assertThat(facts.delegations()).singleElement().satisfies(delegation -> {
            assertThat(delegation.delegator()).isEqualTo("eng-k");
            assertThat(delegation.agentId()).isEqualTo("agt-aabbccddeeff-report");
            assertThat(delegation.objectiveFamily()).isEqualTo("REPORTING");
            assertThat(delegation.summary()).isEqualTo("Prepare the weekly HX-310 report");
            assertThat(delegation.operations()).containsExactly("DOCUMENT_READ");
            assertThat(delegation.resources()).containsExactly("HX-310");
            assertThat(delegation.validFrom()).isEqualTo(time.minus(Duration.ofHours(1)));
            assertThat(delegation.expiresAt()).isEqualTo(time.plus(Duration.ofHours(3)));
            assertThat(delegation.revoked()).isFalse();
        });
        assertThatThrownBy(() -> RunOrchestrator.facts(scenario(List.of(fact), null), "aabbccddeeff", time))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theAgentIsRegisteredWithTheRolesScopeAndAnAccountOnlyForASessionAgent() {
        Map<String, Object> tokensOnly = new RunAgent("aabbccddeeff", reportAgent, false).registration("v-eng-k");
        Map<String, Object> withAccount = new RunAgent("aabbccddeeff", reportAgent, true).registration("v-eng-k");

        // docs/agent OC-3: the registration the engine's agent registration API takes; the engine makes the secrets.
        assertThat(tokensOnly).containsEntry("agentId", "agt-aabbccddeeff-report")
                .containsEntry("clientId", "agt-aabbccddeeff-report-client")
                .containsEntry("sponsorId", "v-eng-k")
                .containsEntry("scopes", List.of("sc.engineer"))
                .containsEntry("displayName", "Report agent")
                .containsEntry("ownToken", true)
                .containsEntry("actsForPeople", true)
                .containsEntry("account", false)
                .doesNotContainKey("clientSecret");
        assertThat(withAccount).containsEntry("account", true).containsEntry("accountGroups", List.of("SC_ENGINEER"));
    }

    @Test
    void theCasesWrittenBeforeAgentsKeepTheirDefinitions() throws Exception {
        for (ScenarioDefinition scenario : new ScenarioCatalog(json).all()) {
            JsonNode tree = json.valueToTree(scenario);
            assertThat(tree.has("agent")).as(scenario.key()).isFalse();
            for (JsonNode step : tree.path("steps")) {
                assertThat(step.has("sender")).as(scenario.key()).isFalse();
            }
            for (JsonNode fact : tree.path("facts")) {
                assertThat(fact.has("delegated")).as(scenario.key()).isFalse();
            }
        }
    }

    @Test
    void theInternalAgentCasesAreOutsideTheCatalog() throws Exception {
        ScenarioDefinition everyone = agentCase("AG0");
        ScenarioDefinition ownPaths = agentCase("AG1");
        ScenarioCatalog catalog = new ScenarioCatalog(json);

        assertThat(catalog.find(everyone.key())).isEmpty();
        assertThat(catalog.find(ownPaths.key())).isEmpty();
        assertThat(everyone.steps()).extracting(ScenarioDefinition.Step::senderOrPerson).containsExactly(
                ScenarioDefinition.Sender.PERSON, ScenarioDefinition.Sender.DELEGATED_AGENT,
                ScenarioDefinition.Sender.AUTONOMOUS_AGENT, ScenarioDefinition.Sender.AGENT_SESSION);
        assertThat(RunOrchestrator.facts(everyone, "aabbccddeeff", Instant.parse("2026-09-30T14:00:00Z"))
                .delegations()).singleElement()
                .satisfies(delegation -> assertThat(delegation.agentId()).isEqualTo("agt-aabbccddeeff-report"));
        assertThat(ownPaths.steps()).extracting(ScenarioDefinition.Step::senderOrPerson).containsExactly(
                ScenarioDefinition.Sender.PERSON, ScenarioDefinition.Sender.AUTONOMOUS_AGENT,
                ScenarioDefinition.Sender.AGENT_SESSION);
        ScenarioDefinition delegatedOnly = agentCase("AG2");
        assertThat(catalog.find(delegatedOnly.key())).isEmpty();
        assertThat(delegatedOnly.steps()).extracting(ScenarioDefinition.Step::senderOrPerson)
                .containsExactly(ScenarioDefinition.Sender.DELEGATED_AGENT);
        assertThat(RunOrchestrator.facts(delegatedOnly, "aabbccddeeff", Instant.parse("2026-09-30T14:00:00Z"))
                .delegations()).hasSize(1);
    }

    /**
     * docs/agent A3-8: the internal learning check quarantines the run's delegation, releases it and removes the
     * agent's learning, each before its step; the cases written before keep their definitions.
     */
    @Test
    void theLearningCheckActsOnTheAgentsLearningBeforeItsSteps() throws Exception {
        ScenarioDefinition learning = agentCase("AG3");

        assertThat(new ScenarioCatalog(json).find(learning.key())).isEmpty();
        assertThat(learning.steps()).extracting(ScenarioDefinition.Step::senderOrPerson).containsExactly(
                ScenarioDefinition.Sender.PERSON, ScenarioDefinition.Sender.DELEGATED_AGENT,
                ScenarioDefinition.Sender.DELEGATED_AGENT, ScenarioDefinition.Sender.DELEGATED_AGENT,
                ScenarioDefinition.Sender.PERSON);
        assertThat(learning.steps()).extracting(step -> step.learningAction() == null ? null
                : step.learningAction().action() + (step.learningAction().forDelegation() ? "/delegation" : ""))
                .containsExactly(null, null, "QUARANTINE/delegation", "RELEASE/delegation", "REMOVE");
        assertThat(learning.steps()).allSatisfy(step -> assertThat(step.learningAction() == null
                || !step.learningAction().reason().isBlank()).isTrue());
        assertThat(RunOrchestrator.facts(learning, "aabbccddeeff", Instant.parse("2026-09-30T14:00:00Z"))
                .delegations()).hasSize(1);
        // A step without an action writes none: the definitions written before keep their hashes.
        assertThat(json.writeValueAsString(agentCase("AG2"))).doesNotContain("learningAction");
    }

    private ScenarioDefinition agentCase(String key) throws Exception {
        try (InputStream in = RunAgentTest.class.getResourceAsStream("/agent-cases/" + key + ".json")) {
            return json.readValue(in, ScenarioDefinition.class);
        }
    }

    @Test
    void anAgentCaseReadsBackFromItsJson() throws Exception {
        ScenarioDefinition written = scenario(List.of(), reportAgent);
        ScenarioDefinition read = json.readValue(json.writeValueAsString(written), ScenarioDefinition.class);

        assertThat(read.agent()).isEqualTo(reportAgent);
        assertThat(read.steps().get(0).senderOrPerson()).isEqualTo(ScenarioDefinition.Sender.DELEGATED_AGENT);
    }

    private static ScenarioDefinition.Step step(ScenarioDefinition.Sender sender) {
        return new ScenarioDefinition.Step(BusinessOperation.DOCUMENT_READ,
                new ScenarioDefinition.DocumentSelector("HX-310", "DRAWING", 1), null, null, null, 0, Map.of(), null,
                null, null, null, null, null, null, null, sender);
    }

    private static ScenarioDefinition scenario(List<ScenarioDefinition.Fact> facts, ScenarioDefinition.Agent agent) {
        return new ScenarioDefinition("AG0", 1, Map.of("en", "Agent paths"), "eng-k", false, TimeSlot.AFTERNOON,
                ScenarioDefinition.Device.USUAL, ScenarioDefinition.Pace.PACED, facts,
                List.of(step(ScenarioDefinition.Sender.DELEGATED_AGENT)),
                new ScenarioDefinition.Oracle("NORMAL", List.of("ALLOW")), null, null, null, agent);
    }
}
