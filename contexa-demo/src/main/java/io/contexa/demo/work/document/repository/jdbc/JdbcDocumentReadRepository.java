package io.contexa.demo.work.document.repository.jdbc;

import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import io.contexa.demo.work.document.dto.DocumentReadResult;
import io.contexa.demo.work.document.repository.DocumentReadRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcDocumentReadRepository extends AbstractJdbcRepository implements DocumentReadRepository {

    public JdbcDocumentReadRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc) {
        super(jdbc);
    }

    @Override
    public void append(DocumentReadResult result) {
        jdbc.update("""
                insert into lab.business_document_read
                    (request_id, document_id, document_version, content_sha256, content_bytes, completed_at)
                values (?, ?, ?, ?, ?, ?)
                """, result.requestId(), result.document().summary().id(), result.document().summary().version(),
                result.contentSha256(), result.contentBytes(), Timestamp.from(result.completedAt()));
    }
}
