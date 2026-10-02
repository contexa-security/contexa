package io.contexa.demo.observation.http.repository.jdbc;

import io.contexa.demo.observation.http.dto.BusinessHttpObservation;
import io.contexa.demo.observation.http.repository.BusinessHttpRepository;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.Optional;
import java.util.UUID;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcBusinessHttpRepository extends AbstractJdbcRepository implements BusinessHttpRepository {

    public JdbcBusinessHttpRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc) {
        super(jdbc);
    }

    @Override
    public void append(BusinessHttpObservation observation) {
        jdbc.update("""
                insert into lab.business_http_observation
                    (request_id, visitor_id, method, path, started_at, completed_at, http_status, failure_type,
                     servlet_output_bytes, output_capture_state, collector_instance_id)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, observation.requestId(), observation.visitorId(), observation.method(), observation.path(),
                Timestamp.from(observation.startedAt()), Timestamp.from(observation.completedAt()),
                observation.httpStatus(), observation.failureType(), observation.servletOutputBytes(),
                observation.outputCaptureState(), observation.collectorInstanceId());
    }

    @Override
    public Optional<BusinessHttpObservation> find(UUID requestId, UUID visitorId) {
        return Optional.ofNullable(first(jdbc.query("""
                select * from lab.business_http_observation where request_id = ? and visitor_id = ?
                """, (rs, row) -> new BusinessHttpObservation(rs.getObject("request_id", UUID.class),
                rs.getObject("visitor_id", UUID.class), rs.getString("method"), rs.getString("path"),
                rs.getTimestamp("started_at").toInstant(), rs.getTimestamp("completed_at").toInstant(),
                rs.getObject("http_status", Integer.class), rs.getString("failure_type"),
                rs.getObject("servlet_output_bytes", Long.class), rs.getString("output_capture_state"),
                rs.getObject("collector_instance_id", UUID.class)), requestId, visitorId)));
    }
}
