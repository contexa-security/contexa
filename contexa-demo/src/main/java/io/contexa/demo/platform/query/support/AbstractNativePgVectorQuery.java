package io.contexa.demo.platform.query.support;

import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.pgvector.PgVectorStore;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcOperations;

public abstract class AbstractNativePgVectorQuery {

    private final VectorStore vectorStore;
    private final Environment environment;

    protected AbstractNativePgVectorQuery(VectorStore vectorStore, Environment environment) {
        this.vectorStore = vectorStore;
        this.environment = environment;
    }

    protected boolean supportsStore() {
        return vectorStore instanceof PgVectorStore;
    }

    protected JdbcOperations nativeClient() {
        Object client = vectorStore.getNativeClient().orElse(null);
        return client instanceof JdbcOperations jdbc ? jdbc : null;
    }

    protected String relation() {
        return quote(environment.getProperty("spring.ai.vectorstore.pgvector.schema-name", "public"))
                + "." + quote(environment.getProperty("spring.ai.vectorstore.pgvector.table-name", "vector_store"));
    }

    private String quote(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            throw new IllegalArgumentException("Missing vector relation identifier");
        }
        return "\"" + identifier.replace("\"", "\"\"") + "\"";
    }
}
