package io.contexa.demo.observation.model.repository.jdbc;

import io.contexa.demo.observation.model.dto.ModelBoundaryObservation;
import io.contexa.demo.observation.model.repository.ModelBoundaryRepository;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.UUID;

@Repository
@Profile("contexa")
public class JdbcModelBoundaryRepository extends AbstractJsonJdbcRepository implements ModelBoundaryRepository {

    public JdbcModelBoundaryRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc, documents);
    }

    @Override
    public void append(ModelBoundaryObservation observation) {
        String json = documents.write(observation);
        var source = observation.source();
        jdbc.update("""
                insert into lab.model_boundary_observation
                    (id, observed_at, input_sha256, payload, content_sha256,
                     request_id, event_id, processing_generation, pipeline_request_id)
                values (?, ?, ?, cast(? as jsonb), ?, ?, ?, ?, ?)
                """, observation.id(), Timestamp.from(observation.startedAt()), observation.inputSha256(),
                json, documents.hash(json), source == null ? null : requestId(source.requestId()),
                source == null ? null : source.eventId(), source == null ? null : source.processingGeneration(),
                source == null ? null : source.pipelineRequestId());
    }

    private UUID requestId(String value) {
        if (value == null) {
            return null;
        }
        try {
            UUID parsed = UUID.fromString(value);
            return parsed.toString().equals(value) ? parsed : null;
        } catch (IllegalArgumentException unsupported) {
            return null;
        }
    }
}
