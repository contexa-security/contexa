package io.contexa.demo.comparison.attestation.source.jdbc;

import io.contexa.demo.comparison.attestation.dto.LoginOrigin;
import io.contexa.demo.comparison.attestation.source.LoginOriginQuery;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcLoginOriginQuery extends AbstractJdbcRepository implements LoginOriginQuery {

    public JdbcLoginOriginQuery(@Qualifier("jdbcTemplate") JdbcOperations jdbc) {
        super(jdbc);
    }

    @Override
    public LoginOrigin find(String sessionSha256, String username) {
        return first(jdbc.query("""
                select id, request_id, occurred_at, request_path, authentication_type, http_status
                from lab.authentication_observation
                where session_sha256=? and username=? and request_method='POST'
                    and request_path='/login' and authenticated_after=true
                    and http_status in (200,302,303)
                order by occurred_at desc,id limit 1
                """, (rs, row) -> new LoginOrigin(rs.getObject("id", UUID.class),
                rs.getObject("request_id", UUID.class), rs.getTimestamp("occurred_at").toInstant(),
                rs.getString("request_path"), rs.getString("authentication_type"), rs.getInt("http_status")),
                sessionSha256, username));
    }
}
