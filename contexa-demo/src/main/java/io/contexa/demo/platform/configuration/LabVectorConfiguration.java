package io.contexa.demo.platform.configuration;

import io.contexa.demo.configuration.properties.LabProperties;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.vectorstore.pgvector.PgVectorStore;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

@Configuration(proxyBeanMethods = false)
@Profile("contexa")
public class LabVectorConfiguration {

    @Bean
    PgVectorStore vectorStore(@Qualifier("contexaDataSource") DataSource securityDataSource,
            @Qualifier("primaryEmbeddingModel") EmbeddingModel embeddingModel,
            LabProperties properties) {
        Integer dimensions = properties.embedding().dimensions();
        if (dimensions == null || dimensions < 128 || dimensions > 3072) {
            throw new IllegalStateException(
                    "LAB_EMBEDDING_DIMENSIONS must specify the real model dimension (128..3072).");
        }
        return PgVectorStore.builder(new JdbcTemplate(securityDataSource), embeddingModel)
                .schemaName("public").vectorTableName("vector_store")
                .dimensions(dimensions).initializeSchema(true).build();
    }
}
