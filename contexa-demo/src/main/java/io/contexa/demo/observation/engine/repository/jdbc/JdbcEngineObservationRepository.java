package io.contexa.demo.observation.engine.repository.jdbc;

import io.contexa.demo.observation.engine.dto.EngineObservation;
import io.contexa.demo.observation.engine.repository.EngineObservationRepository;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.List;
import java.util.UUID;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcEngineObservationRepository extends AbstractJsonJdbcRepository implements EngineObservationRepository {

    public JdbcEngineObservationRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc, documents);
    }

    @Override
    public void append(EngineObservation observation) {
        String json = documents.write(observation);
        jdbc.update("""
                insert into lab.engine_observation (id, request_id, kind, observed_at, payload, content_sha256)
                values (?, ?, ?, ?, cast(? as jsonb), ?)
                """, observation.id(), observation.requestId(), observation.kind(),
                Timestamp.from(observation.observedAt()), json, documents.hash(json));
    }

    @Override
    public List<EngineObservation> find(UUID requestId) {
        return jdbc.query("""
                select payload::text from lab.engine_observation where request_id = ? order by sequence limit 1000
                """, (rs, row) -> documents.read(rs.getString(1), EngineObservation.class), requestId);
    }
}
