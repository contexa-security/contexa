package io.contexa.demo.observation.rag.service.impl;

import io.contexa.demo.observation.rag.dto.RagDocumentFingerprint;
import io.contexa.demo.observation.rag.dto.RagDocumentReadback;
import io.contexa.demo.observation.rag.service.RagDocumentQuery;
import io.contexa.demo.platform.query.support.AbstractNativePgVectorQuery;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.util.UUID;

@Component
@Profile("contexa")
public class NativeRagDocumentQuery extends AbstractNativePgVectorQuery implements RagDocumentQuery {

    public NativeRagDocumentQuery(VectorStore vectorStore, Environment environment) {
        super(vectorStore, environment);
    }

    @Override
    public RagDocumentReadback read(String documentId) {
        Instant readAt = Instant.now();
        if (!supportsStore()) {
            return unavailable("UNSUPPORTED_STORE", readAt);
        }
        try {
            JdbcOperations jdbc = nativeClient();
            if (jdbc == null) {
                return unavailable("UNAVAILABLE", readAt);
            }
            UUID id = UUID.fromString(documentId);
            String sql = """
                    select id::text, encode(sha256(convert_to(content,'UTF8')),'hex') as content_hash,
                        octet_length(content) as content_bytes, metadata->>'eventId' as event_id,
                        metadata->>'documentType' as document_type, embedding is not null as embedding_present,
                        encode(sha256(convert_to(jsonb_build_array(id,content,metadata,embedding::text)::text,
                            'UTF8')),'hex') as row_hash
                    from %s where id = ?
                    """.formatted(relation());
            var rows = jdbc.query(connection -> {
                var statement = connection.prepareStatement(sql);
                statement.setObject(1, id);
                statement.setQueryTimeout(3);
                statement.setMaxRows(1);
                return statement;
            }, (rs, row) -> new RagDocumentReadback("ROW_OBSERVED", readAt,
                    new RagDocumentFingerprint(rs.getString("id"), rs.getString("content_hash"),
                            rs.getInt("content_bytes"), rs.getString("event_id"), rs.getString("document_type")),
                    rs.getBoolean("embedding_present"), rs.getString("row_hash")));
            return rows.isEmpty() ? unavailable("NO_ROW_RETURNED_AT_READ", readAt) : rows.get(0);
        } catch (RuntimeException unavailable) {
            return unavailable("UNAVAILABLE", readAt);
        }
    }

    private RagDocumentReadback unavailable(String state, Instant readAt) {
        return new RagDocumentReadback(state, readAt, null, null, null);
    }
}
