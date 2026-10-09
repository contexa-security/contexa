package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.run.RunFacts;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** Orchestrator pieces that need no running control: scenarios, decision reading, facts, expectations. */
class OrchestratorUnitTest {

    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

    @Test
    void theScenarioCatalogHoldsTheP1ScenariosWithAnExpectationForEveryRuleControl() throws Exception {
        ScenarioCatalog catalog = new ScenarioCatalog(json);

        assertThat(catalog.all()).extracting(ScenarioDefinition::key)
                .containsExactly("A1", "A1T", "A3", "A3A", "A3S", "A3ST", "A3T", "A3TA", "A5", "A5T", "A6", "A6T", "A8", "A8T", "K2", "R1", "S01", "S02",
                        "S03", "S04", "S05", "S06", "S07", "S08", "S09", "S09C", "S10", "S11", "S12", "S13", "S13T");
        for (ScenarioDefinition scenario : catalog.all()) {
            assertThat(scenario.title()).as(scenario.key()).containsKeys("ko", "en");
            assertThat(scenario.frozenOn()).as(scenario.key() + " is frozen (W2-5)").isNotNull();
            assertThat(scenario.oracle().rationale()).as(scenario.key() + " explains its ground truth (R-40)")
                    .containsOnlyKeys("ko", "en");
            assertThat(scenario.oracle().counterpoint()).as(scenario.key() + " states the expected objection (R-16)")
                    .containsOnlyKeys("ko", "en");
            assertThat(catalog.sha256(scenario.key())).as(scenario.key()).hasValueSatisfying(hash ->
                    assertThat(hash).matches("[0-9a-f]{64}"));
            assertThat(scenario.oracle().allowedEngineActions()).as(scenario.key()).isNotEmpty();
            for (ScenarioDefinition.Step step : scenario.steps()) {
                assertThat(step.expected()).as(scenario.key()).containsOnlyKeys("A", "B", "C1", "C2");
                assertThat(Set.copyOf(step.expected().values())).as(scenario.key()).isSubsetOf("ALLOW", "DENY");
            }
        }
        assertThat(catalog.find("S08").orElseThrow().template()).as("the new user has no template").isFalse();
    }

    /** P3-BE-01: the challenge is recognised by the engine's own code and timed from the moment it came back. */
    @Test
    void aChallengeIsRecognisedByTheEnginesCodeAndTimedFromItsAnswer() {
        Instant sent = Instant.parse("2026-10-05T05:00:00Z");
        ControlSession.StepOutcome challenged = new ControlSession.StepOutcome("r-1", "GET", "/api/documents/x", sent,
                401, "REFUSED", 0, "MFA_CHALLENGE_REQUIRED", "verify", null, 40, sent, null);
        ControlSession.StepOutcome forbidden = new ControlSession.StepOutcome("r-2", "GET", "/api/documents/x", sent,
                401, "REFUSED", 0, "UNAUTHORIZED", null, null, 40, sent, null);
        assertThat(ControlSession.challenged(challenged)).isTrue();
        assertThat(ControlSession.challenged(forbidden)).isFalse();
        ControlSession.StepOutcome decidedNow = new ControlSession.StepOutcome("r-4", "POST",
                "/api/projects/GB-500/exports?items=480", sent, 401, "REFUSED", 0, "ZERO_TRUST_CHALLENGE",
                "Additional authentication required", null, 13000, sent, null);
        assertThat(ControlSession.challenged(decidedNow))
                .as("the engine's synchronous CHALLENGE of this very request (W1, H-18)").isTrue();
        ControlSession.StepOutcome blockedBefore = new ControlSession.StepOutcome("r-5", "GET", "/api/documents/x",
                sent, 403, "REFUSED", 0, "ACCOUNT_BLOCKED", null, null, 40, sent, null);
        ControlSession.StepOutcome blockedNow = new ControlSession.StepOutcome("r-6", "POST",
                "/api/projects/GB-500/exports?items=480", sent, 403, "REFUSED", 0, "ZERO_TRUST_BLOCK",
                "Access blocked", null, 13000, sent, null);
        ControlSession.StepOutcome ruleRefusal = new ControlSession.StepOutcome("r-7", "POST",
                "/api/projects/GB-500/exports?items=480", sent, 403, "REFUSED", 0, "C1-NIGHT", null, null, 20, sent,
                null);
        assertThat(ControlSession.blocked(blockedBefore)).as("an earlier BLOCK still in force").isTrue();
        assertThat(ControlSession.blocked(blockedNow))
                .as("the engine's synchronous BLOCK of this very request opens the release (work 2)").isTrue();
        assertThat(ControlSession.blocked(ruleRefusal)).isFalse();

        Instant answeredAt = sent.plusMillis(40);
        ControlSession.StepOutcome reissue = new ControlSession.StepOutcome("r-3", "GET", "/api/documents/x", sent,
                200, "DELIVERED", 1, null, null, null, 35, answeredAt.plusMillis(1900), null);
        RunOrchestrator.ChallengeSummary completed = RunOrchestrator.summary(new ControlSession.ChallengeTrace(true,
                null, answeredAt, answeredAt.plusMillis(120), answeredAt.plusMillis(1850), reissue), false);
        assertThat(completed.codeRequestedMs()).isEqualTo(120);
        assertThat(completed.verifiedMs()).isEqualTo(1850);
        assertThat(completed.reissueSentMs()).isEqualTo(1900);
        assertThat(completed.reissueStatus()).isEqualTo(200);
        assertThat(completed.reissueReanalysed()).isFalse();

        RunOrchestrator.ChallengeSummary abandoned = RunOrchestrator.summary(ControlSession.abandoned(answeredAt), null);
        assertThat(abandoned.answered()).isFalse();
        assertThat(abandoned.reason()).isEqualTo("NO_MAILBOX");
        assertThat(abandoned.reissueSentMs()).isNull();
    }

    @Test
    void theNewestRecordIsTheDecisionAndAParserFailureIsUnresolved() throws Exception {
        JsonNode evidence = json.readTree("""
                {"records":[
                  {"finalAction":"CHALLENGE","proposedAction":"CHALLENGE","technicalFallback":false,
                   "parserFailure":true,"success":false,"failureType":"PARSER_FAILURE",
                   "decidedAt":"2026-10-05T00:00:02Z","metadataJson":"{\\"finalDecisionReasoning\\":\\"r\\"}"},
                  {"finalAction":"ALLOW","success":true,"decidedAt":"2026-10-05T00:00:01Z"}],
                 "events":[{"type":"LAYER1_COMPLETE","mitre":"T1213"}],
                 "modelCalls":[{"promptTokens":100,"completionTokens":20,"totalTokens":120,"promptSha256":"abc",
                                "promptPrincipals":["v111111111111-eng-k","v222222222222-eng-k"]}]}""");

        EngineDecision decision = EngineDecision.from(evidence, true);

        assertThat(decision.finalAction()).isEqualTo("CHALLENGE");
        assertThat(decision.unresolved()).isTrue();
        assertThat(decision.applied()).isEqualTo("BEFORE_RESPONSE");
        assertThat(decision.mitre()).isEqualTo("T1213");
        assertThat(decision.totalTokens()).isEqualTo(120);
        assertThat(decision.reasoning()).isEqualTo("r");
        assertThat(RunOrchestrator.firstPromptSha(decision)).isEqualTo("abc");
        assertThat(RunOrchestrator.foreignPrincipals(decision, "v111111111111-eng-k"))
                .containsExactly("v222222222222-eng-k");
        assertThat(EngineDecision.from(json.readTree("{\"records\":[]}"), false)).isNull();
    }

    @Test
    void ruleControlsAreAsExpectedOnlyWhenEveryOutcomeMatches() {
        Map<String, String> expected = Map.of("A", "ALLOW", "B", "ALLOW", "C1", "DENY", "C2", "DENY");

        assertThat(RunOrchestrator.rulesAsExpected(expected, Map.of("A", "DELIVERED", "B", "DELIVERED",
                "C1", "REFUSED", "C2", "REFUSED", "D", "REFUSED"))).isTrue();
        assertThat(RunOrchestrator.rulesAsExpected(expected, Map.of("A", "DELIVERED", "B", "DELIVERED",
                "C1", "DELIVERED", "C2", "REFUSED", "D", "DELIVERED"))).isFalse();
    }

    @Test
    void scenarioFactsBecomeRunFactsAroundTheCompanyTime() throws Exception {
        ScenarioDefinition scenario = new ScenarioCatalog(json).find("S03").orElseThrow();
        Instant time = Instant.parse("2026-09-30T03:17:00Z");

        RunFacts facts = RunOrchestrator.facts(scenario, "aabbccddeeff", time);

        assertThat(facts.tickets()).singleElement().satisfies(ticket -> {
            assertThat(ticket.ticketKey()).startsWith("TCK-aabbccddeeff-");
            assertThat(ticket.requester()).isEqualTo("eng-k");
            assertThat(ticket.validFrom()).isEqualTo(Instant.parse("2026-09-30T02:17:00Z"));
            assertThat(ticket.validUntil()).isEqualTo(Instant.parse("2026-09-30T07:17:00Z"));
        });
        assertThat(RunOrchestrator.hostIn("10.40.21.0/24", 77)).isEqualTo("10.40.21.77");
        assertThat(List.of(facts.approvals().size(), facts.oncall().size())).containsExactly(0, 0);
    }

    /**
     * W2-5, case S12: the approval's decision is recorded 20 minutes after the request while its validity starts two
     * hours before it; the other approvals of the cases leave the decision time unrecorded.
     */
    @Test
    void anApprovalFactCarriesWhenItsDecisionWasRecordedOnlyWhenTheCaseSaysSo() throws Exception {
        ScenarioCatalog catalog = new ScenarioCatalog(json);
        Instant time = Instant.parse("2026-09-30T14:20:00Z");

        RunFacts late = RunOrchestrator.facts(catalog.find("S12").orElseThrow(), "aabbccddeeff", time);
        RunFacts transfer = RunOrchestrator.facts(catalog.find("A3T").orElseThrow(), "aabbccddeeff", time);

        assertThat(late.approvals()).singleElement().satisfies(approval -> {
            assertThat(approval.approvedAt()).isEqualTo(Instant.parse("2026-09-30T14:40:00Z"));
            assertThat(approval.validFrom()).isEqualTo(Instant.parse("2026-09-30T12:20:00Z"));
        });
        assertThat(transfer.approvals()).singleElement()
                .satisfies(approval -> assertThat(approval.approvedAt()).isNull());
    }

    @Test
    void aTravelFactBecomesATripAndTheRunConnectsFromItsNetwork() throws Exception {
        ScenarioDefinition travel = new ScenarioCatalog(json).find("A1T").orElseThrow();
        ScenarioDefinition external = new ScenarioCatalog(json).find("A1").orElseThrow();
        Instant time = Instant.parse("2026-09-30T09:40:00Z");

        RunFacts facts = RunOrchestrator.facts(travel, "aabbccddeeff", time);

        assertThat(facts.travel()).singleElement().satisfies(trip -> {
            assertThat(trip.planKey()).isEqualTo("TRV-aabbccddeeff-1");
            assertThat(trip.networkCidr()).isEqualTo("198.51.100.0/24");
            assertThat(trip.validFrom()).isEqualTo(Instant.parse("2026-09-28T09:40:00Z"));
        });
        assertThat(RunOrchestrator.network(travel, "10.40.21.0/24")).isEqualTo("198.51.100.0/24");
        assertThat(RunOrchestrator.network(external, "10.40.21.0/24")).isEqualTo(RunOrchestrator.EXTERNAL_NETWORK);
        assertThat(RunOrchestrator.network(new ScenarioCatalog(json).find("S01").orElseThrow(), "10.40.21.0/24"))
                .isEqualTo("10.40.21.0/24");
    }

    @Test
    void aClaimNamesTheRunsOwnTicketAndOnCallDutyBecomesARunFact() throws Exception {
        ScenarioDefinition legitimate = new ScenarioCatalog(json).find("A8T").orElseThrow();
        ScenarioDefinition attack = new ScenarioCatalog(json).find("A8").orElseThrow();
        Instant time = Instant.parse("2026-09-30T20:30:00Z");

        RunFacts facts = RunOrchestrator.facts(legitimate, "aabbccddeeff", time);

        assertThat(facts.tickets()).singleElement().extracting(RunFacts.Ticket::ticketKey)
                .isEqualTo("TCK-aabbccddeeff-1");
        assertThat(facts.oncall()).singleElement().satisfies(duty -> {
            assertThat(duty.employeeKey()).isEqualTo("adm-a");
            assertThat(duty.startsAt()).isEqualTo(Instant.parse("2026-09-30T18:30:00Z"));
        });
        assertThat(RunOrchestrator.claim(legitimate.steps().get(0), "aabbccddeeff"))
                .isEqualTo("&claimedTicket=TCK-aabbccddeeff-1");
        assertThat(RunOrchestrator.claim(attack.steps().get(0), "aabbccddeeff")).isEqualTo("&claimedTicket=INC-7781");
    }

    /**
     * H-18: the code of a refusal is read from every body the controls answer with, the engine's synchronous decision
     * included (its body was read without a code, so its CHALLENGE never opened the identity check).
     */
    @Test
    void theRefusalCodeIsReadFromEveryBodyTheControlsAnswerWith() throws Exception {
        JsonNode engineDecision = json.readTree("{\"status\":401,\"code\":\"ZERO_TRUST_CHALLENGE\","
                + "\"message\":\"Additional authentication required\",\"action\":\"CHALLENGE\","
                + "\"resourceId\":\"ContexaBusinessOperations.exportDocuments\",\"riskScore\":null,"
                + "\"analysisTimeout\":false,\"timestamp\":\"2026-10-06T14:15:26.903029800Z\"}");
        assertThat(ControlSession.ruleOf(engineDecision)).isEqualTo("ZERO_TRUST_CHALLENGE");
        assertThat(ControlSession.ruleOf(json.readTree("{\"error\":\"MFA_CHALLENGE_REQUIRED\"}")))
                .isEqualTo("MFA_CHALLENGE_REQUIRED");
        assertThat(ControlSession.ruleOf(json.readTree("{\"rule\":\"C2-APPROVAL-MISSING\",\"error\":\"Forbidden\"}")))
                .as("a plain control's rule wins over the generic error").isEqualTo("C2-APPROVAL-MISSING");
        assertThat(ControlSession.ruleOf(json.readTree("{\"message\":\"nothing else\"}"))).isNull();
    }
}
