package io.contexa.showcase.portal.journey;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Work 14 of docs/showcase/화면설계서-v2-구현계획.md on a real database: the journey is kept by the visitor's hash only,
 * survives a reload, scores the visitor's call against the case's ground truth, refuses an invalid change, and leaves
 * with the visitor.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
class JourneyIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final String VISITOR = "a".repeat(64);

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("showcase.internal.signing-key", JourneyIntegrationTest::randomKey);
    }

    @Autowired
    JourneyViews journey;

    @Autowired
    JdbcTemplate jdbc;

    @Test
    void theJourneyIsKeptScoredAndLeavesWithTheVisitor() {
        jdbc.update("insert into visitor (visitor_hash) values (?)", VISITOR);

        JourneyViews.View first = journey.view(VISITOR);
        assertThat(first.state().act()).as("a new visitor starts before the first act").isZero();
        assertThat(first.runs()).isEmpty();

        journey.update(VISITOR, new JourneyViews.Update("DEFAULT", 1, "scene", 2, null)).orElseThrow();
        journey.update(VISITOR, new JourneyViews.Update(null, null, "predict", 1,
                new JourneyViews.Prediction("E1", "CHALLENGE", "SOME", null))).orElseThrow();
        JourneyViews.View reloaded = journey.view(VISITOR);

        assertThat(reloaded.state().act()).isEqualTo(1);
        assertThat(reloaded.state().step()).isEqualTo("predict");
        assertThat(reloaded.state().differences()).containsExactly(1, 2);
        assertThat(reloaded.predictions()).singleElement().satisfies(score -> {
            assertThat(score.caseKey()).isEqualTo("A3");
            assertThat(score.engineRight()).as("CHALLENGE is a right answer to the attacker's case").isTrue();
            assertThat(score.existingActual()).as("the visitor has not sent it yet").isNull();
        });

        assertThat(journey.update(VISITOR, new JourneyViews.Update("ELSEWHERE", null, null, null, null))).isEmpty();
        assertThat(journey.update(VISITOR, new JourneyViews.Update(null, null, null, 7, null))).isEmpty();
        assertThat(journey.update(VISITOR, new JourneyViews.Update(null, null, "Scene/1", null, null))).isEmpty();
        assertThat(journey.view(VISITOR).state().step()).as("an invalid change stores nothing").isEqualTo("predict");

        jdbc.update("delete from visitor where visitor_hash = ?", VISITOR);
        assertThat(jdbc.queryForObject("select count(*) from visitor_journey where visitor_hash = ?", Integer.class,
                VISITOR)).isZero();
    }

    /** Works 15 and 18, ADR-35: a visitor is counted once per act and once per answered question, and anonymously. */
    @Test
    void actsAndAnswersAreCountedOnceWithoutTheVisitor() {
        String visitor = "c".repeat(64);
        jdbc.update("insert into visitor (visitor_hash) values (?)", visitor);

        journey.update(visitor, new JourneyViews.Update(null, 1, "scene", null, null)).orElseThrow();
        journey.update(visitor, new JourneyViews.Update(null, 1, "result", null, null)).orElseThrow();
        journey.update(visitor, new JourneyViews.Update(null, 2, "scene", null, null)).orElseThrow();
        JourneyViews.QuizResult first = journey.answer(visitor,
                Map.of("Q1", "USUAL_AND_COMPANY", "Q2", "PASSWORD", "Q3", "SYNC")).orElseThrow();
        JourneyViews.QuizResult again = journey.answer(visitor,
                Map.of("Q1", "USUAL_AND_COMPANY", "Q2", "COMPANY_APPROVAL", "Q3", "SYNC")).orElseThrow();

        assertThat(first.right()).isEqualTo(2);
        assertThat(first.answers()).filteredOn(answer -> !answer.right()).singleElement().satisfies(answer -> {
            assertThat(answer.correct()).isEqualTo("COMPANY_APPROVAL");
            assertThat(answer.revisit()).as("back to the screen of difference 3").isEqualTo(3);
        });
        assertThat(first.counted()).isTrue();
        assertThat(again.right()).isEqualTo(3);
        assertThat(again.counted()).as("a visitor's answers are counted once").isFalse();
        assertThat(journey.answer(visitor, Map.of("Q1", "SOMETHING"))).as("not an option").isEmpty();

        assertThat(jdbc.queryForList("select metric || ' ' || item || ' ' || value || ' ' || count from anonymous_tally"
                + " order by metric, item, value", String.class)).containsExactly("ACT_REACHED 1 - 1",
                "ACT_REACHED 2 - 1", "QUIZ Q1 RIGHT 1", "QUIZ Q2 WRONG 1", "QUIZ Q3 RIGHT 1");
        assertThat(jdbc.queryForList("select column_name from information_schema.columns"
                + " where table_name = 'anonymous_tally' order by ordinal_position", String.class))
                .as("no column names or links a visitor").containsExactly("day", "metric", "item", "value", "count");
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
