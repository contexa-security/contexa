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
 * O-4: the vector store Contexa's decisions are stored in uses the Contexa database, also when the application's
 * default JdbcTemplate is its own database (the application owns sign-in); a store the application declares is kept.
 */
class ContexaPgVectorStoreAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ContexaPgVectorStoreAutoConfiguration.class,
                    PgVectorStoreAutoConfiguration.class))
            .withPropertyValues("spring.ai.vectorstore.pgvector.initialize-schema=false");

    @Test
    void theVectorStoreUsesTheContexaDatabaseNotTheApplicationsOwn() {
        runner.withUserConfiguration(TwoDatabases.class).run(context -> {
            assertThat(context).hasSingleBean(PgVectorStore.class);
            PgVectorStore store = context.getBean(PgVectorStore.class);
            assertThat(ReflectionTestUtils.getField(store, "jdbcTemplate"))
                    .isSameAs(context.getBean("contexaJdbcTemplate"));
        });
    }

    @Test
    void aVectorStoreTheApplicationDeclaresIsKeptAndContexaAddsNone() {
        runner.withUserConfiguration(TwoDatabases.class, OwnVectorStore.class).run(context -> {
            assertThat(context).hasBean("applicationVectorStore");
            // Spring AI's own store, if it makes one next to the application's, stays as it was.
            assertThat(context.getBeansOfType(PgVectorStore.class).values())
                    .allSatisfy(store -> assertThat(ReflectionTestUtils.getField(store, "jdbcTemplate"))
                            .isNotSameAs(context.getBean("contexaJdbcTemplate")));
        });
    }

    @Test
    void withoutTheContexaDatabaseSpringAisStoreIsLeftAsItWas() {
        runner.withUserConfiguration(ApplicationDatabaseOnly.class).run(context -> {
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
    }

    @Configuration(proxyBeanMethods = false)
    static class OwnVectorStore {

        @Bean
        VectorStore applicationVectorStore() {
            return mock(VectorStore.class);
        }
    }
}
