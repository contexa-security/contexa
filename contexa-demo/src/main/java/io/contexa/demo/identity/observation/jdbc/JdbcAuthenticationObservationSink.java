package io.contexa.demo.identity.observation.jdbc;

import io.contexa.demo.identity.observation.AuthenticationObservationSink;
import io.contexa.demo.identity.observation.dto.AuthenticationHttpObservation;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.UUID;

@Repository
public class JdbcAuthenticationObservationSink extends AbstractJdbcRepository implements AuthenticationObservationSink {

    public JdbcAuthenticationObservationSink(@Qualifier("jdbcTemplate") JdbcOperations jdbc) {
        super(jdbc);
    }

    public void record(AuthenticationHttpObservation value) {
        jdbc.update("""
                        insert into lab.authentication_observation(id,username,event_type,occurred_at,request_id,http_status,role,
                            request_method,request_path,authenticated_before,authenticated_after,authentication_type,session_sha256)
                        values(?,?,'HTTP_AUTHENTICATION_RESPONSE',?,?,?,?,?,?,?,?,?,?)
                        """, UUID.randomUUID(), value.username(), Timestamp.from(value.occurredAt()), value.requestId(),
                value.status(), value.role(),
                value.method(), value.path(), value.authenticatedBefore(), value.authenticatedAfter(),
                value.authenticationType(), value.sessionSha256());
    }
}
