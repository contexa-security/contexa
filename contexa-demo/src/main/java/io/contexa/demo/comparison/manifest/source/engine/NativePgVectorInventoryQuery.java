package io.contexa.demo.comparison.manifest.source.engine;

import io.contexa.demo.comparison.manifest.dto.RagInventorySnapshot;
import io.contexa.demo.comparison.manifest.source.RagInventoryQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.platform.query.support.AbstractNativePgVectorQuery;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Component;
import java.time.Instant;

@Component
@Profile("contexa")
public class NativePgVectorInventoryQuery extends AbstractNativePgVectorQuery implements RagInventoryQuery {

    private static final int DOCUMENT_LIMIT = 5000;
    private static final String SCOPE = "CONFIGURED_CORPUS_SNAPSHOT_NOT_RETRIEVAL_OR_AUTHORIZATION_RESULT";
    private final DocumentCodec documents;

    public NativePgVectorInventoryQuery(VectorStore vectorStore, Environment environment,
            DocumentCodec documents) {
        super(vectorStore, environment);
        this.documents = documents;
    }

    @Override
    public RagInventorySnapshot capture() {
        Instant capturedAt = Instant.now();
        if (!supportsStore()) {
            return snapshot("UNSUPPORTED_STORE", capturedAt, null, null);
        }
        JdbcOperations jdbc = nativeClient();
        if (jdbc == null) {
            return snapshot("UNAVAILABLE", capturedAt, null, null);
        }
        String sql = """
                select encode(sha256(convert_to(jsonb_build_array(id,content,metadata,embedding::text)::text,
                    'UTF8')),'hex') as row_hash from %s order by id limit %d
                """.formatted(relation(), DOCUMENT_LIMIT + 1);
        try {
            // The native store's client is read only here; all rows belong to one PostgreSQL statement snapshot.
            var hashes = jdbc.query(connection -> {
                var statement = connection.prepareStatement(sql);
                statement.setQueryTimeout(3);
                statement.setFetchSize(128);
                return statement;
            }, (rs, row) -> rs.getString("row_hash"));
            if (hashes.size() > DOCUMENT_LIMIT) {
                return snapshot("SIZE_LIMIT", capturedAt, hashes.size(), null);
            }
            return snapshot("CAPTURED", capturedAt, hashes.size(), documents.hash(String.join("\n", hashes)));
        } catch (RuntimeException unavailable) {
            return snapshot("UNAVAILABLE", capturedAt, null, null);
        }
    }

    private RagInventorySnapshot snapshot(String state, Instant capturedAt, Integer count, String hash) {
        return new RagInventorySnapshot(state, "NATIVE_PGVECTOR_CLIENT_CONFIGURED_TABLE", capturedAt,
                count, DOCUMENT_LIMIT, hash, SCOPE);
    }
}
