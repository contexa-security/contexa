package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.contexa.showcase.business.work.BusinessOperation;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * docs/agent RL-3: the history of usual work an agent of a case brings, so that its decisions are not all those of a
 * stranger. It is the agent's own usual operations (its tools that its delegation allows), on the days before the
 * case, sent on the path of the case's work.
 */
class AgentHistoryTest {

    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules()
            .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

    private static ScenarioDefinition load(String key) throws IOException {
        try (InputStream stream = AgentHistoryTest.class.getResourceAsStream("/agent-tasks/" + key + ".json")) {
            assertThat(stream).as(key).isNotNull();
            return JSON.readValue(stream, ScenarioDefinition.class);
        }
    }

    @Test
    void anExportingCaseBringsSixDaysOfListsReadsAndTheUsualExport() throws IOException {
        // M19A: tools list and export; its delegation allows project list, document list and export.
        ScenarioDefinition scenario = load("M19A");

        ScenarioDefinition withHistory = AgentHistory.apply(scenario, AgentHistory.USUAL_WORK);

        List<ScenarioDefinition.Step> all = withHistory.steps().subList(0,
                withHistory.steps().size() - scenario.steps().size());
        // The agent acts for a person, so the person's own work comes first (see the next test); the rest is the agent's.
        List<ScenarioDefinition.Step> added = all.subList(1, all.size());
        assertThat(added).hasSize(6 * 2);
        assertThat(added).extracting(ScenarioDefinition.Step::operation)
                .containsOnly(BusinessOperation.DOCUMENT_LIST, BusinessOperation.EXPORT);
        assertThat(added).filteredOn(step -> step.operation() == BusinessOperation.EXPORT)
                .allSatisfy(step -> assertThat(step.items()).isEqualTo(40));
        // The days before the case, in order, all before the case's own first step at 0, on the case's path.
        assertThat(all).extracting(ScenarioDefinition.Step::offsetSeconds).isSorted().allMatch(offset -> offset < 0);
        assertThat(added.get(0).offsetSeconds()).isEqualTo(-6 * 86400L);
        assertThat(added).allSatisfy(step -> assertThat(step.sender()).isEqualTo(scenario.task().sender()));
        // The case's own steps follow, the first of them on a new day and so in a session of its own; the rest as they were.
        List<ScenarioDefinition.Step> own = withHistory.steps().subList(all.size(), withHistory.steps().size());
        assertThat(own.get(0)).isEqualTo(scenario.steps().get(0).startingSession());
        assertThat(own.subList(1, own.size())).isEqualTo(scenario.steps().subList(1, scenario.steps().size()));
        assertThat(withHistory.task()).isEqualTo(scenario.task());
    }

    @Test
    void anAgentThatActsForAPersonBringsThePersonsOwnWorkFirstAndOthersDoNot() throws IOException {
        // The engine asks a person for the one-time code at a sign-in only when the person has no earlier ALLOW: a
        // history of the agent's requests alone leaves every day's sign-in with a code, and the case's own day,
        // after the person's own ALLOW, without one (the real server, 2026-10-25: M19L, "login method PASSWORD seen
        // 0 of 12"). A person who has an agent has work of their own before it.
        ScenarioDefinition scenario = load("M19A");
        assertThat(scenario.task().sender()).isEqualTo(ScenarioDefinition.Sender.DELEGATED_AGENT);

        ScenarioDefinition delegated = AgentHistory.apply(scenario, AgentHistory.USUAL_WORK);

        ScenarioDefinition.Step first = delegated.steps().get(0);
        assertThat(first.senderOrPerson()).isEqualTo(ScenarioDefinition.Sender.PERSON);
        assertThat(first.operation()).isEqualTo(BusinessOperation.DOCUMENT_LIST);
        assertThat(first.offsetSeconds()).isLessThan(delegated.steps().get(1).offsetSeconds());
        assertThat(first.startsNewSession()).isFalse();
        assertThat(delegated.steps().stream().filter(step ->
                step.senderOrPerson() == ScenarioDefinition.Sender.PERSON).count()).isEqualTo(1 + scenario.steps()
                .stream().filter(step -> step.senderOrPerson() == ScenarioDefinition.Sender.PERSON).count());

        // On the agent's own credentials or its own account there is no person behind the sign-in.
        for (ScenarioDefinition.Sender path : List.of(ScenarioDefinition.Sender.AUTONOMOUS_AGENT,
                ScenarioDefinition.Sender.AGENT_SESSION)) {
            ScenarioDefinition other = AgentHistory.apply(scenario.onPath(path), AgentHistory.USUAL_WORK);
            assertThat(other.steps().get(0).senderOrPerson()).isEqualTo(path);
        }
    }

    @Test
    void everyDayOfTheHistoryIsASessionOfItsOwnAndSoIsTheDayOfTheCase() throws IOException {
        // An agent's days are sessions, as a person's are: a history in one session of six days old would teach the
        // engine one login only, and the case's first session of its own would read as a stranger's (the real server,
        // 2026-10-25: M19L with the history, "login method PASSWORD seen 0 of 12").
        ScenarioDefinition scenario = load("M19A");

        ScenarioDefinition withHistory = AgentHistory.apply(scenario, AgentHistory.USUAL_WORK);

        List<ScenarioDefinition.Step> added = withHistory.steps().subList(1,
                withHistory.steps().size() - scenario.steps().size());
        List<ScenarioDefinition.Step> firstOfDay = added.stream().filter(step -> step.offsetSeconds() % 86400L == 0)
                .toList();
        assertThat(firstOfDay).hasSize(6);
        // The agent acts for a person: the run's own sign-in is the person's step, and every day of the agent signs in
        // again, after the person's own ALLOW, so that all of them read the same way (no code asked, as the case's).
        assertThat(firstOfDay).allSatisfy(step -> assertThat(step.startsNewSession()).isTrue());
        assertThat(added).filteredOn(ScenarioDefinition.Step::startsNewSession).hasSize(6);
        assertThat(withHistory.steps().get(1 + added.size()).startsNewSession()).isTrue();

        // On the agent's own credentials the first day is the run's own sign-in; each later day signs in again.
        ScenarioDefinition solo = AgentHistory.apply(scenario.onPath(ScenarioDefinition.Sender.AUTONOMOUS_AGENT),
                AgentHistory.USUAL_WORK);
        List<ScenarioDefinition.Step> soloDays = solo.steps().stream()
                .filter(step -> step.offsetSeconds() % 86400L == 0 && step.offsetSeconds() < 0).toList();
        assertThat(soloDays).hasSize(6);
        assertThat(soloDays.get(0).startsNewSession()).isFalse();
        assertThat(soloDays.subList(1, 6)).allSatisfy(step -> assertThat(step.startsNewSession()).isTrue());
    }

    @Test
    void aCaseWithNoScriptedStepsStartsTheWorkInASessionOfItsOwn() throws IOException {
        ScenarioDefinition scenario = load("M13A");
        assertThat(scenario.steps()).isEmpty();
        assertThat(scenario.task().startsNewSession()).isFalse();

        ScenarioDefinition withHistory = AgentHistory.apply(scenario, AgentHistory.USUAL_WORK);

        assertThat(withHistory.task().startsNewSession()).isTrue();
        assertThat(withHistory.task()).isEqualTo(scenario.task().startingSession());
        // A case that already starts its own session keeps the task as it is.
        ScenarioDefinition own = load("M19A");
        assertThat(own.task().startsNewSession()).isTrue();
        assertThat(AgentHistory.apply(own, AgentHistory.USUAL_WORK).task()).isEqualTo(own.task());
    }

    @Test
    void aReadingCaseBringsReadsAndNoExportBecauseItsDelegationAllowsNone() throws IOException {
        // M13A: reads only (project list, document list, document read).
        ScenarioDefinition withHistory = AgentHistory.apply(load("M13A"), AgentHistory.USUAL_WORK);

        int person = withHistory.task().sender() == ScenarioDefinition.Sender.DELEGATED_AGENT ? 1 : 0;
        assertThat(withHistory.steps()).hasSize(person + 6 * (1 + AgentHistory.READS_PER_DAY));
        assertThat(withHistory.steps()).extracting(ScenarioDefinition.Step::operation)
                .containsOnly(BusinessOperation.DOCUMENT_LIST, BusinessOperation.DOCUMENT_READ);
        assertThat(withHistory.steps()).filteredOn(step -> step.operation() == BusinessOperation.DOCUMENT_READ)
                .allSatisfy(step -> assertThat(step.document()).isNotNull());
    }

    @Test
    void theDelegationOfTheCaseStartsBeforeTheHistoryDoes() throws IOException {
        ScenarioDefinition scenario = load("M13A");
        Duration before = scenario.facts().stream().filter(fact -> "DELEGATION".equals(fact.kind()))
                .findFirst().orElseThrow().validFromOffset();

        ScenarioDefinition withHistory = AgentHistory.apply(scenario, AgentHistory.USUAL_WORK);

        Duration after = withHistory.facts().stream().filter(fact -> "DELEGATION".equals(fact.kind()))
                .findFirst().orElseThrow().validFromOffset();
        assertThat(before).isEqualTo(Duration.ofHours(-1));
        assertThat(after).isEqualTo(Duration.ofSeconds(-6 * 86400L - 3600));
        // The facts that are no delegation are not touched.
        assertThat(withHistory.facts().stream().filter(fact -> !"DELEGATION".equals(fact.kind())).toList())
                .isEqualTo(scenario.facts().stream().filter(fact -> !"DELEGATION".equals(fact.kind())).toList());
    }

    @Test
    void theHistoryFollowsThePathOfTheCase() throws IOException {
        ScenarioDefinition scenario = load("M19A");

        ScenarioDefinition onSolo = scenario.onPath(ScenarioDefinition.Sender.AUTONOMOUS_AGENT);

        ScenarioDefinition solo = AgentHistory.apply(onSolo, AgentHistory.USUAL_WORK);

        // The steps the history added are the agent's, on the path of the case; the case's own steps are as they were.
        int added = solo.steps().size() - onSolo.steps().size();
        assertThat(added).isEqualTo(6 * 2);
        assertThat(solo.steps().subList(0, added)).allSatisfy(step -> assertThat(step.sender())
                .isEqualTo(ScenarioDefinition.Sender.AUTONOMOUS_AGENT));
        assertThat(solo.steps().get(added)).isEqualTo(onSolo.steps().get(0).startingSession());
        assertThat(solo.steps().subList(added + 1, solo.steps().size()))
                .isEqualTo(onSolo.steps().subList(1, onSolo.steps().size()));
    }

    @Test
    void aCaseThatWorksInThePersonsOwnSessionKeepsThePersonsBaselineAndGetsNoHistory() throws IOException {
        // The agent that uses the person's own session has the person's baseline (a learned template): there is no
        // cold start to remove, and six days of a second history would only thin out what the template says.
        ScenarioDefinition scenario = load("M05A");
        assertThat(scenario.task().sender()).isEqualTo(ScenarioDefinition.Sender.PERSON);

        assertThat(AgentHistory.apply(scenario, AgentHistory.USUAL_WORK)).isSameAs(scenario);
    }

    @Test
    void anUnknownProfileOrACaseWithoutAnAgentIsRefused() throws IOException {
        assertThat(AgentHistory.known(AgentHistory.USUAL_WORK)).isTrue();
        assertThat(AgentHistory.known("OTHER")).isFalse();
        assertThat(AgentHistory.known(null)).isFalse();
        assertThatThrownBy(() -> AgentHistory.apply(load("M19A"), "OTHER"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
