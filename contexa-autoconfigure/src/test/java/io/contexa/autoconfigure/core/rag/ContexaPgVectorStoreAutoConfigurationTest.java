package io.contexa.autoconfigure.core.rag;

import org.junit.jupiter.api.Test;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.pgvector.PgVectorStore;
import org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * O-4: the vector store Contexa's decisions are stored in uses the Contexa database, also when the application's default JdbcTemplate is its own
 * database (the application owns sign-in). It is Contexa's own bean and not a default candidate: the application's VectorStore (declared, or made by
 * Spring AI's auto-configuration from its own database) is neither replaced nor shared, and Contexa's documents never go to it.
 */
class ContexaPgVectorStoreAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ContexaPgVectorStoreAutoConfiguration.class,
                    PgVectorStoreAutoConfiguration.class))
            .withPropertyValues("spring.ai.vectorstore.pgvector.initialize-schema=false");

    /** text-embedding-3-large produces 3072 by itself, and the database would only say that the index failed. */
    @Test
    void aSizeTheIndexCannotHoldIsRefusedWithWhatToDo() {
        runner.withUserConfiguration(TwoDatabases.class)
                .withPropertyValues("contexa.vectorstore.pgvector.dimensions=3072",
                        "contexa.vectorstore.pgvector.initialize-schema=true")
                .run(context -> assertThat(context.getStartupFailure()).rootCause()
                        .hasMessageContaining("at most 2000 dimensions and 3072 were asked for")
                        .hasMessageContaining("contexa.vectorstore.pgvector.initialize-schema=false"));
    }

    @Test
    void aTableTheApplicationMadeItselfIsNotJudged() {
        runner.withUserConfiguration(TwoDatabases.class)
                .withPropertyValues("contexa.vectorstore.pgvector.dimensions=3072",
                        "contexa.vectorstore.pgvector.initialize-schema=false")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void theVectorStoreUsesTheContexaDatabaseNotTheApplicationsOwn() {
        runner.withUserConfiguration(TwoDatabases.class).run(context -> {
            PgVectorStore contexas = context.getBean("contexaVectorStore", PgVectorStore.class);
            assertThat(ReflectionTestUtils.getField(contexas, "jdbcTemplate")).isSameAs(context.getBean("contexaJdbcTemplate"));
        });
    }

    @Test
    void theApplicationsOwnStoreOfSpringAiIsStillMadeFromItsOwnDatabase() {
        runner.withUserConfiguration(TwoDatabases.class).run(context -> {
            assertThat(context.getBeansOfType(PgVectorStore.class)).containsOnlyKeys("contexaVectorStore", "vectorStore");
            PgVectorStore applications = context.getBean("vectorStore", PgVectorStore.class);
            assertThat(ReflectionTestUtils.getField(applications, "jdbcTemplate")).isSameAs(context.getBean("jdbcTemplate"));
            assertThat(context.getBeanProvider(VectorStore.class).getIfAvailable())
                    .as("what an injection point of the application gets by type").isSameAs(applications);
        });
    }

    @Test
    void aVectorStoreTheApplicationDeclaresIsKeptAndContexaKeepsItsOwn() {
        runner.withUserConfiguration(TwoDatabases.class, OwnVectorStore.class).run(context -> {
            assertThat(context).hasBean("applicationVectorStore");
            // the application has its own store and Spring AI's, as it would alone; Contexa's is a third, hidden from the injection by type
            assertThat(context.getBeansOfType(VectorStore.class)).containsOnlyKeys("applicationVectorStore", "vectorStore", "contexaVectorStore");
            PgVectorStore contexas = context.getBean("contexaVectorStore", PgVectorStore.class);
            assertThat(ReflectionTestUtils.getField(contexas, "jdbcTemplate")).isSameAs(context.getBean("contexaJdbcTemplate"));
        });
    }

    @Test
    void withoutTheContexaDatabaseSpringAisStoreIsLeftAsItWas() {
        runner.withUserConfiguration(ApplicationDatabaseOnly.class).run(context -> {
            assertThat(context).doesNotHaveBean("contexaVectorStore");
            PgVectorStore store = context.getBean(PgVectorStore.class);
            assertThat(ReflectionTestUtils.getField(store, "jdbcTemplate")).isSameAs(context.getBean("jdbcTemplate"));
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationDatabaseOnly {

        @Bean
        @Primary
        JdbcTemplate jdbcTemplate() {
            return mock(JdbcTemplate.class);
        }

        @Bean
        EmbeddingModel embeddingModel() {
            return mock(EmbeddingModel.class);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class TwoDatabases extends ApplicationDatabaseOnly {

        @Bean(defaultCandidate = false)
        JdbcTemplate contexaJdbcTemplate() {
            return mock(JdbcTemplate.class);
        }

        @Bean(name = "contexaPrimaryEmbeddingModel", defaultCandidate = false)
        EmbeddingModel contexaPrimaryEmbeddingModel() {
            return mock(EmbeddingModel.class);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class OwnVectorStore {

        @Bean
        VectorStore applicationVectorStore() {
            return mock(VectorStore.class);
        }
    }
}
