package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.run.RunFacts;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;

/** Orchestrator pieces that need no running control: scenarios, decision reading, facts, expectations. */
class OrchestratorUnitTest {

    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

    @Test
    void theScenarioCatalogHoldsTheP1ScenariosWithAnExpectationForEveryRuleControl() throws Exception {
        ScenarioCatalog catalog = new ScenarioCatalog(json);

        assertThat(catalog.all()).extracting(ScenarioDefinition::key)
                .containsExactly("A1", "A1T", "A3", "A3A", "A3S", "A3ST", "A3T", "A3TA", "A5", "A5T", "A6", "A6T", "A8", "A8T", "K2", "R1", "S01", "S02",
                        "S03", "S04", "S05", "S06", "S07", "S08", "S09", "S09C", "S10", "S11", "S11T", "S12", "S13",
                        "S13T", "S14", "S15");
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

    /**
     * N-SRC-3: every sealed decision of the run is inspected before the clean-up; a package stored late is asked for
     * again, one never stored and one that fails are counted as missing, and a failure stops asking for it.
     */
    @Test
    void theSealedDecisionsAreInspectedAndALatePackageIsAskedForAgain() {
        Map<String, Integer> asked = new LinkedHashMap<>();
        RunOrchestrator.SealInspector inspector = requestId -> {
            int times = asked.merge(requestId, 1, Integer::sum);
            if ("req-failing".equals(requestId)) {
                throw new IOException("control D is down");
            }
            boolean stored = "req-1".equals(requestId) || ("req-late".equals(requestId) && times >= 3);
            return stored ? Optional.of(json.createObjectNode()) : Optional.empty();
        };

        Map<String, Object> counts = RunOrchestrator.inspectSealed(List.of("req-1", "req-late", "req-never",
                "req-failing"), inspector, Duration.ZERO, 4);

        assertThat(counts).containsEntry("requested", 4).containsEntry("inspected", 2);
        assertThat(counts.get("missing")).isEqualTo(List.of("req-never", "req-failing"));
        assertThat(asked).containsEntry("req-1", 1).containsEntry("req-late", 3).containsEntry("req-never", 4)
                .containsEntry("req-failing", 1);
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

    /** W7-4 (plan 8.7): a step's request parts are its body as JSON, its headers and the earlier id it names. */
    @Test
    void aStepsRequestPartsAreItsBodyItsHeadersAndTheIdOfTheEarlierRequestItNames() throws Exception {
        ScenarioDefinition.Step plain = new ScenarioDefinition.Step(BusinessOperation.EXPORT, null, "GB-500", null,
                4831, 0, Map.of(), null, null, null, null);
        ScenarioDefinition.Step named = new ScenarioDefinition.Step(BusinessOperation.EXPORT, null, "GB-500", null,
                4831, 0, Map.of(), null, null, null, null, Map.of("note", "text"),
                Map.of("X-Contexa-Anomaly-Signal", "benign; text"), 1);

        ControlSession.RequestParts parts = RunOrchestrator.requestParts(json, named, Map.of(1, "id-of-step-1"));

        assertThat(parts.body()).isEqualTo("{\"note\":\"text\"}");
        assertThat(parts.headers()).containsExactly(entry("X-Contexa-Anomaly-Signal", "benign; text"),
                entry("X-Request-ID", "id-of-step-1"));
        assertThat(RunOrchestrator.requestParts(json, plain, Map.of())).isEqualTo(ControlSession.RequestParts.NONE);
        assertThatThrownBy(() -> RunOrchestrator.requestParts(json, named, Map.of()))
                .as("the earlier step sent nothing").isInstanceOf(IllegalStateException.class);
        assertThat(RunOrchestrator.path(named, "aabbccddeeff", null))
                .isEqualTo("/api/projects/GB-500/exports?items=4831");
        assertThat(RunOrchestrator.path(new ScenarioDefinition.Step(BusinessOperation.DOCUMENT_READ,
                new ScenarioDefinition.DocumentSelector("HX-310", "DRAWING", 1), null, null, null, 0, Map.of(), null,
                null, null, null), "aabbccddeeff", "HX-310-DWG-00001")).isEqualTo("/api/documents/HX-310-DWG-00001");
    }

    /** W7-4: a definition whose request parts cannot be sent as written is refused before its run creates anything. */
    @Test
    void aDefinitionWhoseRequestPartsCannotBeSentAsWrittenIsRefused() throws Exception {
        ScenarioDefinition.Step listing = new ScenarioDefinition.Step(BusinessOperation.PROJECT_LIST, null, null, null,
                null, -60, Map.of(), null, null, null, null);
        ScenarioDefinition.Step readWithBody = new ScenarioDefinition.Step(BusinessOperation.DOCUMENT_READ,
                new ScenarioDefinition.DocumentSelector("HX-310", "DRAWING", 1), null, null, null, 0, Map.of(), null,
                null, null, null, Map.of("note", "text"), null, null);
        ScenarioDefinition.Step signedHeader = exportWith(Map.of("X-Showcase-Request-Id", "chosen"), null);
        ScenarioDefinition.Step ownId = exportWith(null, 1);
        ScenarioDefinition.Step twice = exportWith(Map.of("x-request-id", "chosen"), 1);

        assertThatThrownBy(() -> RunOrchestrator.checkRequestParts(definition(List.of(readWithBody))))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RunOrchestrator.checkRequestParts(definition(List.of(signedHeader))))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RunOrchestrator.checkRequestParts(definition(List.of(ownId))))
                .as("step 1 has no earlier step").isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RunOrchestrator.checkRequestParts(definition(List.of(listing, twice))))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatCode(() -> RunOrchestrator.checkRequestParts(definition(List.of(listing, exportWith(null, 1)))))
                .doesNotThrowAnyException();
        for (ScenarioDefinition scenario : new ScenarioCatalog(json).all()) {
            assertThatCode(() -> RunOrchestrator.checkRequestParts(scenario)).as(scenario.key())
                    .doesNotThrowAnyException();
        }
    }

    /**
     * W7-4: a step that names no request part is written as before, so every packaged case keeps the definition hash
     * its runs were stored under (run.scenario_sha256, the way ExecutionSpecHasherTest keeps an older specification's
     * hash); a step that names one writes it.
     */
    @Test
    void theRequestPartsLeaveTheDefinitionHashOfEveryPackagedCaseAsItWas() throws Exception {
        List<String> before = List.of("operation", "document", "project", "customer", "items", "offsetSeconds",
                "expected", "claimedTicket", "grantee", "responsibility", "visitorSends");
        for (ScenarioDefinition scenario : new ScenarioCatalog(json).all()) {
            for (JsonNode step : json.valueToTree(scenario).path("steps")) {
                List<String> names = new ArrayList<>();
                step.fieldNames().forEachRemaining(names::add);
                assertThat(names).as(scenario.key()).containsExactlyInAnyOrderElementsOf(before);
            }
            List<ScenarioDefinition.Step> rebuilt = scenario.steps().stream().map(step -> new ScenarioDefinition.Step(
                    step.operation(), step.document(), step.project(), step.customer(), step.items(),
                    step.offsetSeconds(), step.expected(), step.claimedTicket(), step.grantee(), step.responsibility(),
                    step.visitorSends())).toList();
            assertThat(RunOrchestrator.definitionSha256(json, withSteps(scenario, rebuilt))).as(scenario.key())
                    .isEqualTo(RunOrchestrator.definitionSha256(json, scenario));
        }
        String repeated = RunOrchestrator.canonicalJson(json.valueToTree(exportWith(null, 1)));
        assertThat(repeated).contains("\"requestIdOf\":1").doesNotContain("\"body\"").doesNotContain("\"headers\"");
    }

    /** W7-4: the request parts of a definition survive writing it and reading it back. */
    @Test
    void aStepsRequestPartsSurviveTheRoundTripOfItsDefinition() throws Exception {
        ScenarioDefinition.Step listing = new ScenarioDefinition.Step(BusinessOperation.PROJECT_LIST, null, null, null,
                null, -60, Map.of("A", "ALLOW"), null, null, null, null);
        ScenarioDefinition.Step export = new ScenarioDefinition.Step(BusinessOperation.EXPORT, null, "GB-500", null,
                4831, 0, Map.of("A", "ALLOW"), null, null, null, null, Map.of("note", "text"),
                Map.of("X-Contexa-Anomaly-Signal", "benign; text"), 1);
        ScenarioDefinition definition = definition(List.of(listing, export));

        ScenarioDefinition read = json.readValue(json.writeValueAsString(definition), ScenarioDefinition.class);

        assertThat(read).isEqualTo(definition);
        assertThat(read.steps().get(1).body()).isEqualTo(Map.of("note", "text"));
        assertThat(read.steps().get(1).headers()).isEqualTo(Map.of("X-Contexa-Anomaly-Signal", "benign; text"));
        assertThat(read.steps().get(1).requestIdOf()).isEqualTo(1);
        assertThat(RunOrchestrator.definitionSha256(json, read)).isEqualTo(RunOrchestrator.definitionSha256(json,
                definition));
    }

    /**
     * W7-5: the new bundle is normal work in combinations the rules were not written for, counted apart under its own
     * suite: a new laptop on a registered trip at the company's dawn, usual work on a resource of internal grade, and
     * the requests of S11 under an approval they stay within.
     */
    @Test
    void theNewBundleIsNormalWorkInCombinationsTheBenchmarkCountsApart() throws Exception {
        ScenarioCatalog catalog = new ScenarioCatalog(json);

        assertThat(catalog.all()).filteredOn(scenario -> ScenarioDefinition.NORMAL_COMBINATION.equals(scenario.suite()))
                .extracting(ScenarioDefinition::key).containsExactly("S11T", "S14", "S15");
        for (String key : List.of("S11T", "S14", "S15")) {
            ScenarioDefinition scenario = catalog.find(key).orElseThrow();
            assertThat(scenario.version()).isEqualTo(1);
            assertThat(scenario.frozenOn()).isEqualTo(LocalDate.parse("2026-10-16"));
            assertThat(scenario.oracle().classification()).as(key).isEqualTo("NORMAL");
            assertThat(scenario.oracle().allowedEngineActions()).as(key).containsExactly("ALLOW", "CHALLENGE");
            assertThat(scenario.template()).as(key).isTrue();
        }
        ScenarioDefinition trip = catalog.find("S14").orElseThrow();
        assertThat(trip.protagonist()).isEqualTo("eng-k");
        assertThat(trip.timeSlot()).isEqualTo(TimeSlot.DAWN);
        assertThat(trip.device()).isEqualTo(ScenarioDefinition.Device.NEW);
        assertThat(trip.networkOrDefault()).isEqualTo(ScenarioDefinition.Network.TRAVEL);
        assertThat(RunOrchestrator.network(trip, "10.40.21.0/24")).isEqualTo("198.51.100.0/24");
        ScenarioDefinition internal = catalog.find("S15").orElseThrow();
        assertThat(internal.steps()).allSatisfy(step -> assertThat(step.project() != null ? step.project()
                : step.document().project()).isEqualTo("PLM-OPS"));
        ScenarioDefinition within = catalog.find("S11T").orElseThrow();
        ScenarioDefinition beyond = catalog.find("S11").orElseThrow();
        assertThat(within.steps()).as("the same requests as S11").isEqualTo(beyond.steps());
        int sum = within.steps().stream().mapToInt(ScenarioDefinition.Step::items).sum();
        assertThat(sum).isEqualTo(2400).isLessThanOrEqualTo(within.facts().get(0).maxItems())
                .isGreaterThan(beyond.facts().get(0).maxItems());
    }

    /**
     * N-INJ-5 (plan 8.7, the label of a request that becomes a past record): a step that starts a new session is sent
     * with the later steps in a session of their own. The engine leaves a request's own session out of its past
     * records (W3-18), so the allowed requests of the earlier session become past records of the later steps. The run
     * signs in before its first step, so the first step cannot start one.
     */
    @Test
    void aStepThatStartsANewSessionIsSentWithTheLaterStepsInASessionOfTheirOwn() throws Exception {
        ScenarioDefinition.Step first = readOf(1, null);
        ScenarioDefinition.Step again = readOf(2, true);

        assertThat(RunOrchestrator.sessionNumbers(definition(List.of(first, again, readOf(3, null)))))
                .containsExactly(1, 2, 2);
        assertThat(RunOrchestrator.sessionNumbers(definition(List.of(first, readOf(2, false))))).containsExactly(1, 1);
        assertThatThrownBy(() -> RunOrchestrator.checkRequestParts(definition(List.of(again, first))))
                .as("the run signs in before its first step").isInstanceOf(IllegalArgumentException.class);
        for (ScenarioDefinition scenario : new ScenarioCatalog(json).all()) {
            assertThat(RunOrchestrator.sessionNumbers(scenario)).as(scenario.key()).containsOnly(1);
        }
        ScenarioDefinition pastRecordLabel = variant("A1T-I1");
        assertThat(RunOrchestrator.sessionNumbers(pastRecordLabel)).containsExactly(1, 2, 2);
        assertThatCode(() -> RunOrchestrator.checkRequestParts(pastRecordLabel)).doesNotThrowAnyException();
        assertThat(RunOrchestrator.facts(pastRecordLabel, "aabbccddeeff", Instant.parse("2026-09-30T09:40:00Z"))
                .documents()).singleElement().extracting(RunFacts.Document::documentKey)
                .as("the key the injection row's reachedBy names").isEqualTo("DOC-aabbccddeeff-2");
    }

    /**
     * N-INJ-5: the run signs in two minutes before the company time, or two minutes before its first step when that
     * step comes earlier, so every packaged case and every earlier variant keeps the sign-in time its runs had.
     */
    @Test
    void theRunSignsInBeforeItsFirstStep() throws Exception {
        Instant companyTime = Instant.parse("2026-09-30T00:00:00Z");
        Instant usual = companyTime.minus(Duration.ofMinutes(2));
        assertThat(RunOrchestrator.SIGN_IN_LEAD).isEqualTo(Duration.ofMinutes(2));
        for (ScenarioDefinition scenario : new ScenarioCatalog(json).all()) {
            assertThat(RunOrchestrator.signInTime(scenario, companyTime)).as(scenario.key()).isEqualTo(usual);
        }
        List<String> keys = new ArrayList<>();
        for (Resource resource : new PathMatchingResourcePatternResolver()
                .getResources("classpath*:reactivity/variants/*.json")) {
            ScenarioDefinition variant;
            try (InputStream in = resource.getInputStream()) {
                variant = json.readValue(in, ScenarioDefinition.class);
            }
            keys.add(variant.key());
            assertThat(RunOrchestrator.signInTime(variant, companyTime)).as(variant.key()).isEqualTo(
                    "A1T-I1".equals(variant.key()) ? Instant.parse("2026-09-29T23:48:00Z") : usual);
        }
        assertThat(keys).as("the variants read").contains("A3-I3", "A1T-I1");
    }

    /** N-INJ-5: a new session survives the round trip of its definition, and only a step that starts one names it. */
    @Test
    void aNewSessionSurvivesTheRoundTripAndOnlyAStepThatStartsOneNamesIt() throws Exception {
        ScenarioDefinition definition = definition(List.of(readOf(1, null), readOf(2, true)));

        ScenarioDefinition read = json.readValue(json.writeValueAsString(definition), ScenarioDefinition.class);

        assertThat(read).isEqualTo(definition);
        assertThat(read.steps()).extracting(ScenarioDefinition.Step::startsNewSession).containsExactly(false, true);
        assertThat(RunOrchestrator.canonicalJson(json.valueToTree(readOf(2, true)))).contains("\"newSession\":true");
        assertThat(RunOrchestrator.canonicalJson(json.valueToTree(readOf(1, null)))).doesNotContain("newSession");
    }

    private static ScenarioDefinition.Step readOf(int position, Boolean newSession) {
        return new ScenarioDefinition.Step(BusinessOperation.DOCUMENT_READ,
                new ScenarioDefinition.DocumentSelector("HX-310", "DRAWING", position), null, null, null,
                60L * position, Map.of(), null, null, null, null, null, null, null, newSession);
    }

    private ScenarioDefinition variant(String key) throws IOException {
        try (InputStream stream = getClass().getResourceAsStream("/reactivity/variants/" + key + ".json")) {
            assertThat(stream).as(key).isNotNull();
            return json.readValue(stream, ScenarioDefinition.class);
        }
    }

    private static ScenarioDefinition.Step exportWith(Map<String, String> headers, Integer requestIdOf) {
        return new ScenarioDefinition.Step(BusinessOperation.EXPORT, null, "GB-500", null, 4831, 0, Map.of(), null,
                null, null, null, null, headers, requestIdOf);
    }

    private static ScenarioDefinition definition(List<ScenarioDefinition.Step> steps) {
        return new ScenarioDefinition("T", 1, Map.of("ko", "시험", "en", "test"), "adm-a", true, TimeSlot.DAWN,
                ScenarioDefinition.Device.USUAL, ScenarioDefinition.Pace.PACED, List.of(), steps,
                new ScenarioDefinition.Oracle("THREAT", List.of("BLOCK")), null);
    }

    private static ScenarioDefinition withSteps(ScenarioDefinition scenario, List<ScenarioDefinition.Step> steps) {
        return new ScenarioDefinition(scenario.key(), scenario.version(), scenario.title(), scenario.protagonist(),
                scenario.template(), scenario.timeSlot(), scenario.device(), scenario.pace(), scenario.facts(), steps,
                scenario.oracle(), scenario.network(), scenario.frozenOn(), scenario.suite());
    }
}
