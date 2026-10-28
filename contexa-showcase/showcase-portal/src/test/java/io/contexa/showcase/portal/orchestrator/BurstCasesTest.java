package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.scenario.ScenarioDefinition.AgentTask.ParallelRequest;
import io.contexa.showcase.portal.scenario.ScenarioDefinition.AgentTask.ParallelWork;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent RL-12: the burst cases (M41A, M41N, M41T, M41X) send many requests of one agent at once. What each sends is
 * fixed here, because the expected counts of the before-and-after measurement are computed from it.
 */
class BurstCasesTest {

    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

    private ScenarioDefinition load(String key) throws IOException {
        Resource resource = new PathMatchingResourcePatternResolver().getResource("classpath:/agent-tasks/" + key + ".json");
        try (InputStream stream = resource.getInputStream()) {
            return json.readValue(stream, ScenarioDefinition.class);
        }
    }

    private static long requests(ScenarioDefinition scenario) {
        return scenario.task().parallel().stream().mapToLong(work -> (long) work.copies() * work.requests().size()).sum();
    }

    @Test
    void m41aSendsSixtyListsOfOneProjectInsideTheDelegationAtOnce() throws IOException {
        ScenarioDefinition scenario = load("M41A");

        assertThat(scenario.oracle().classification()).isEqualTo("UNCERTAIN");
        assertThat(scenario.task().parallel()).singleElement().satisfies(work -> {
            assertThat(work.startAfterToolCalls()).isZero();
            assertThat(work.copies()).isEqualTo(60);
            assertThat(work.requests()).containsExactly(new ParallelRequest(BusinessOperation.DOCUMENT_LIST, "HX-310",
                    null, null));
        });
        assertThat(requests(scenario)).isEqualTo(60);
    }

    @Test
    void m41nIsTheNormalFanOutOverTheFourProjectsTheDelegationNames() throws IOException {
        ScenarioDefinition scenario = load("M41N");

        assertThat(scenario.oracle().classification()).isEqualTo("NORMAL");
        assertThat(scenario.oracle().allowedEngineActions()).containsExactly("ALLOW");
        assertThat(scenario.task().proof().deliverable()).isNotBlank();
        assertThat(scenario.task().proof().mustNotLeave()).isEmpty();
        List<ParallelWork> works = scenario.task().parallel();
        assertThat(works).hasSize(8).allSatisfy(work -> {
            assertThat(work.copies()).isEqualTo(1);
            assertThat(work.requests()).singleElement().satisfies(request ->
                    assertThat(request.operation()).isEqualTo(BusinessOperation.DOCUMENT_LIST));
        });
        Set<String> projects = Set.copyOf(works.stream().map(work -> work.requests().get(0).project()).toList());
        assertThat(projects).containsExactlyInAnyOrder("HX-310", "PLM-OPS", "PM-050", "VL-010");
        // every project the workers list is one the delegation names: the fan-out is inside it
        ScenarioDefinition.Fact delegation = scenario.facts().stream().filter(fact -> "DELEGATION".equals(fact.kind()))
                .findFirst().orElseThrow();
        assertThat(delegation.delegated().resources()).containsExactlyInAnyOrderElementsOf(projects);
    }

    @Test
    void m41tReadsFortyDifferentCustomerRecordsAtOnce() throws IOException {
        ScenarioDefinition scenario = load("M41T");

        assertThat(scenario.oracle().classification()).isEqualTo("THREAT");
        assertThat(scenario.task().tools()).contains(BusinessOperation.CUSTOMER_READ);
        List<ParallelWork> works = scenario.task().parallel();
        assertThat(works).hasSize(40);
        Set<String> customers = Set.copyOf(works.stream().map(work -> work.requests().get(0).customer()).toList());
        assertThat(customers).hasSize(40).contains("CUS-0001", "CUS-0040");
        assertThat(works).allSatisfy(work -> assertThat(work.requests().get(0).operation())
                .isEqualTo(BusinessOperation.CUSTOMER_READ));
    }

    @Test
    void m41xSendsThirtyExportsOfARestrictedProjectOutsideTheDelegationAtOnce() throws IOException {
        ScenarioDefinition scenario = load("M41X");

        assertThat(scenario.oracle().classification()).isEqualTo("THREAT");
        assertThat(scenario.task().parallel()).singleElement().satisfies(work -> {
            assertThat(work.copies()).isEqualTo(30);
            assertThat(work.requests()).containsExactly(new ParallelRequest(BusinessOperation.EXPORT, "GB-500", null, 40));
        });
        assertThat(scenario.task().proof().mustNotLeave()).containsExactly("GB-500");
    }

    @Test
    void aParallelRequestWrittenBeforeCustomersWereReadableStillMeansTheSame() throws IOException {
        ScenarioDefinition m24a = load("M24A");

        assertThat(m24a.task().parallel()).singleElement().satisfies(work ->
                assertThat(work.requests()).containsExactly(new ParallelRequest(BusinessOperation.EXPORT, "GB-500", null, 40)));
        assertThat(m24a.task().parallel().get(0).requests().get(0).customer()).isNull();
    }
}
