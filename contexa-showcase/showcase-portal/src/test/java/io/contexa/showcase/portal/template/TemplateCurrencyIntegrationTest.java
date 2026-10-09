package io.contexa.showcase.portal.template;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Template currency (docs/showcase/계획대조-검수.md N-8): the version key changes with every version a template
 * depends on, a run may clone only a template learned under the versions in force, a newly READY template retires the
 * employee's earlier ones, and the maintainer learns exactly the employees that have no current template. Skipped
 * without Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
class TemplateCurrencyIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final ObjectMapper JSON = new ObjectMapper();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("showcase.internal.signing-key", TemplateCurrencyIntegrationTest::randomKey);
    }

    @Autowired
    JdbcTemplate jdbc;

    @Autowired
    ObjectMapper springJson;

    @Test
    void theVersionKeyChangesWithEveryVersionATemplateDependsOn() throws Exception {
        JsonNode engine = engine("gpt-5-nano", "abc123");
        JsonNode company = JSON.readTree("{\"dataSha256\":\"" + "d".repeat(64) + "\"}");
        String key = TemplateVersions.key(engine, company);

        assertThat(TemplateVersions.key(engine("gpt-5-nano", "abc123"), company)).isEqualTo(key);
        assertThat(TemplateVersions.key(engine("gpt-5-mini", "abc123"), company)).isNotEqualTo(key);
        assertThat(TemplateVersions.key(engine("gpt-5-nano", "def456"), company)).isNotEqualTo(key);
        assertThat(TemplateVersions.key(engine, JSON.readTree("{\"dataSha256\":\"" + "e".repeat(64) + "\"}")))
                .isNotEqualTo(key);
    }

    @Test
    void onlyATemplateLearnedUnderTheVersionsInForceIsCurrentAndANewOneRetiresTheOld() {
        jdbc.update("delete from engine_template");
        TemplateStore store = new TemplateStore(new NamedParameterJdbcTemplate(jdbc), JSON);
        store.start("tpl-old", "adm-a", 1, LocalDate.of(2026, 10, 5), "c".repeat(64), 1, "m", "e", "k1", null);
        store.ready("tpl-old", JSON.createObjectNode(), null);
        store.start("tpl-new", "adm-a", 1, LocalDate.of(2026, 10, 5), "c".repeat(64), 1, "m", "e", "k2",
                Map.of("layer1Model", Map.of("reasoningEffort", "low", "maxOutputTokens", 2048)));
        assertThat(jdbc.queryForObject("select model_settings #>> '{layer1Model,reasoningEffort}' || ' ' || "
                + "(model_settings #>> '{layer1Model,maxOutputTokens}') from engine_template where template_id = 'tpl-new'",
                String.class)).as("the settings it was learned under (W1-3c)").isEqualTo("low 2048");

        assertThat(store.current("adm-a", "k1")).map(TemplateStore.ReadyTemplate::templateId).contains("tpl-old");
        assertThat(store.current("adm-a", "k2")).as("still learning").isEmpty();
        assertThat(store.learningSince("adm-a", Instant.now().minus(Duration.ofMinutes(5)))).isTrue();

        store.ready("tpl-new", JSON.createObjectNode(), null);

        assertThat(store.current("adm-a", "k2")).map(TemplateStore.ReadyTemplate::templateId).contains("tpl-new");
        assertThat(store.current("adm-a", "k1")).as("the earlier template is retired").isEmpty();
        assertThat(jdbc.queryForObject("select status || ' ' || (retired_at is not null) from engine_template "
                + "where template_id = 'tpl-old'", String.class)).isEqualTo("RETIRED true");
        assertThat(store.learningSince("adm-a", Instant.now().minus(Duration.ofMinutes(5)))).isFalse();

        store.start("tpl-broken", "eng-k", 1, LocalDate.of(2026, 10, 5), "c".repeat(64), 1, "m", "e", "k2", null);
        store.failed("tpl-broken", "engine said no");
        assertThat(store.failedSince("eng-k", Instant.now().minus(Duration.ofMinutes(5)))).isTrue();
        assertThat(store.failedSince("adm-a", Instant.now().minus(Duration.ofMinutes(5)))).isFalse();
    }

    @Test
    void theMaintainerLearnsOnlyEmployeesWithoutACurrentTemplate() throws Exception {
        jdbc.update("delete from engine_template");
        TemplateStore store = new TemplateStore(new NamedParameterJdbcTemplate(jdbc), JSON);
        store.start("tpl-adm", "adm-a", 1, LocalDate.of(2026, 10, 5), "c".repeat(64), 1, "m", "e", "k-now", null);
        store.ready("tpl-adm", JSON.createObjectNode(), null);
        store.start("tpl-eng", "eng-k", 1, LocalDate.of(2026, 10, 5), "c".repeat(64), 1, "m", "e", "k-before", null);
        store.ready("tpl-eng", JSON.createObjectNode(), null);
        TemplateCurrency currency = new TemplateCurrency(null, store, Clock.systemUTC()) {
            @Override
            public synchronized String currentKey() {
                return "k-now";
            }
        };
        List<String> learned = new ArrayList<>();
        TemplateMaintainer maintainer = new TemplateMaintainer(new ScenarioCatalog(springJson), currency, store,
                employee -> {
                    learned.add(employee);
                    return "tpl-learned-" + employee;
                }, Clock.fixed(Instant.now(), ZoneOffset.UTC));

        TemplateMaintainer.Check check = maintainer.check();

        assertThat(maintainer.employees()).containsExactly("adm-a", "eng-k");
        assertThat(learned).as("eng-k's template was learned under other versions").containsExactly("eng-k");
        assertThat(check.employees()).isEqualTo(Map.of("adm-a", "CURRENT", "eng-k", "LEARNED"));

        store.start("tpl-eng-2", "eng-k", 1, LocalDate.of(2026, 10, 5), "c".repeat(64), 1, "m", "e", "k-now", null);
        store.failed("tpl-eng-2", "engine said no");
        learned.clear();
        assertThat(maintainer.check().employees()).containsEntry("eng-k", "WAITING_AFTER_FAILURE");
        assertThat(learned).as("no loop on a failing engine").isEmpty();
        maintainer.close();
    }

    /**
     * W2-7: the protagonists the business database scripts work for (the lab's employees) are kept current as well;
     * when the business database cannot be read, the scenarios' protagonists still are.
     */
    @Test
    void theMaintainerAlsoKeepsTheBusinessDatabasesProtagonists() throws Exception {
        TemplateStore store = new TemplateStore(new NamedParameterJdbcTemplate(jdbc), JSON);
        TemplateCurrency currency = new TemplateCurrency(null, store, Clock.systemUTC());
        TemplateMaintainer.Learner none = employee -> null;

        TemplateMaintainer withBusiness = new TemplateMaintainer(new ScenarioCatalog(springJson),
                () -> List.of("adm-a", "adm-c", "eng-01"), currency, store, none, Clock.systemUTC());
        TemplateMaintainer unreadable = new TemplateMaintainer(new ScenarioCatalog(springJson), () -> {
            throw new IOException("business application down");
        }, currency, store, none, Clock.systemUTC());

        assertThat(withBusiness.employees()).containsExactly("adm-a", "adm-c", "eng-01", "eng-k");
        assertThat(unreadable.employees()).containsExactly("adm-a", "eng-k");
        withBusiness.close();
        unreadable.close();
    }

    private static JsonNode engine(String chatModel, String commit) {
        return JSON.valueToTree(Map.of("codeCommit", commit, "engineVersion", "0.1.0", "effectiveMode", "ENFORCE",
                "endpointProtection", Map.of("exportDocuments", "sync"), "chatModel", chatModel,
                "embeddingModel", "text-embedding-3-small", "embeddingDimensions", 1024, "timeZone", "UTC"));
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
