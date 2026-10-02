package io.contexa.demo.work.request.repository.jdbc;

import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.export.dto.ExportRequestSnapshot;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;
import io.contexa.demo.work.request.dto.WorkRequestSnapshot;
import io.contexa.demo.work.customer.dto.CustomerRequestSnapshot;
import io.contexa.demo.work.shared.dto.BusinessResourceFacts;
import io.contexa.demo.work.request.repository.BusinessRequestRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.Optional;
import java.util.UUID;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcBusinessRequestRepository extends AbstractJsonJdbcRepository implements BusinessRequestRepository {

    public JdbcBusinessRequestRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc, documents);
    }

    @Override
    public void append(WorkRequestSnapshot snapshot) {
        String json = documents.write(snapshot);
        BusinessResourceFacts resource = snapshot.resourceFacts();
        boolean document = "DOCUMENT".equals(resource.type());
        boolean customer = "CUSTOMER".equals(resource.type());
        jdbc.update("""
                insert into lab.business_request_snapshot
                    (request_id, visitor_id, workspace_id, username, document_id, document_version,
                     observed_at, snapshot, content_sha256, resource_type, customer_id, customer_version)
                values (?, ?, ?, ?, ?, ?, ?, cast(? as jsonb), ?, ?, ?, ?)
                """, snapshot.requestId(), snapshot.participant().visitorId(), snapshot.participant().workspaceId(),
                snapshot.participant().username(), document ? resource.id() : null, document ? resource.version() : null,
                Timestamp.from(snapshot.observedAt()), json, documents.hash(json), resource.type(),
                customer ? resource.id() : null, customer ? resource.version() : null);
    }

    @Override
    public Optional<WorkRequestSnapshot> find(UUID requestId) {
        return Optional.ofNullable(first(jdbc.query("""
                select resource_type,snapshot::text from lab.business_request_snapshot where request_id=?
                """, (rs, row) -> decode(rs.getString(1), rs.getString(2)), requestId)));
    }

    private WorkRequestSnapshot decode(String type, String json) {
        return switch (type) {
            case "DOCUMENT" -> documents.read(json, BusinessRequestSnapshot.class);
            case "CUSTOMER" -> documents.read(json, CustomerRequestSnapshot.class);
            case "EXPORT" -> documents.read(json, ExportRequestSnapshot.class);
            default -> throw new IllegalStateException("Unsupported business snapshot type: " + type);
        };
    }
}
