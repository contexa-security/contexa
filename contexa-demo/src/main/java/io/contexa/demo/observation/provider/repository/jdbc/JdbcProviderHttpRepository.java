package io.contexa.demo.observation.provider.repository.jdbc;

import io.contexa.demo.observation.provider.dto.ProviderHttpObservation;
import io.contexa.demo.observation.provider.repository.ProviderHttpRepository;
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
public class JdbcProviderHttpRepository extends AbstractJsonJdbcRepository implements ProviderHttpRepository {

    public JdbcProviderHttpRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc, documents);
    }

    @Override
    public void append(ProviderHttpObservation observation) {
        var source = observation.call().source();
        String payload = documents.write(observation);
        jdbc.update("""
                insert into lab.provider_http_observation
                    (id, model_observation_id, request_id, observed_at, payload, content_sha256)
                values (?, ?, ?, ?, cast(? as jsonb), ?)
                """, observation.id(), observation.call().observationId(), UUID.fromString(source.requestId()),
                Timestamp.from(observation.startedAt()), payload, documents.hash(payload));
    }
}
