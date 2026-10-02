package io.contexa.demo.shared.persistence;

import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.jdbc.core.JdbcOperations;

public abstract class AbstractJsonJdbcRepository extends AbstractJdbcRepository {

    protected final DocumentCodec documents;

    protected AbstractJsonJdbcRepository(JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc);
        this.documents = documents;
    }
}
