package io.contexa.demo.observation.stream.repository.jdbc;

import io.contexa.demo.observation.stream.dto.ObservationNotice;
import io.contexa.demo.observation.stream.repository.ObservationFeedRepository;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

public class JdbcObservationFeedRepository extends AbstractJdbcRepository implements ObservationFeedRepository {

    public JdbcObservationFeedRepository(JdbcOperations jdbc) {
        super(jdbc);
    }

    @Override
    public void checkCursor(UUID requestId, UUID visitorId, long after) {
        if (after == 0) {
            return;
        }
        Boolean exists = jdbc.queryForObject("""
                select exists(select 1 from lab.engine_observation event
                    join lab.business_http_observation http on http.request_id=event.request_id
                    where event.request_id=? and http.visitor_id=? and event.sequence=?)
                """, Boolean.class, requestId, visitorId, after);
        if (!Boolean.TRUE.equals(exists)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "INVALID_OBSERVATION_CURSOR");
        }
    }

    @Override
    public List<ObservationNotice> read(UUID requestId, UUID visitorId, long after) {
        return jdbc.query("""
                select event.sequence, event.id, event.request_id, event.kind, event.observed_at,
                    event.collected_at, event.content_sha256 from lab.engine_observation event
                join lab.business_http_observation http on http.request_id=event.request_id
                where event.request_id=? and http.visitor_id=? and event.sequence>?
                order by event.sequence limit 32
                """, (rs, row) -> new ObservationNotice(rs.getLong("sequence"), rs.getObject("id", UUID.class),
                rs.getObject("request_id", UUID.class), rs.getString("kind"),
                rs.getTimestamp("observed_at").toInstant(), rs.getTimestamp("collected_at").toInstant(),
                rs.getString("content_sha256")), requestId, visitorId, after);
    }
}
