package io.contexa.demo.workspace.repository.jdbc;

import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import io.contexa.demo.workspace.dto.WorkspaceView;
import io.contexa.demo.workspace.repository.WorkspaceRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@Repository
@Profile("portal")
public class JdbcWorkspaceRepository extends AbstractJsonJdbcRepository implements WorkspaceRepository {

    public JdbcWorkspaceRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc, DocumentCodec codec) {
        super(jdbc, codec);
    }

    public WorkspaceView getOrCreate(UUID visitorId, List<String> accounts, Instant expiry) {
        jdbc.update(
                "insert into lab.workspace(id,visitor_id,allowed_accounts,expires_at) "
                        + "values(?,?,?::jsonb,?) on conflict(visitor_id) do update set expires_at=excluded.expires_at "
                        + "where workspace.state='PREPARING' and not exists "
                        + "(select 1 from lab.workspace_lease l where l.workspace_id=workspace.id)",
                UUID.randomUUID(), visitorId, documents.write(accounts), Timestamp.from(expiry));
        return find(visitorId);
    }

    public WorkspaceView find(UUID visitorId) {
        return first(jdbc.query(
                "select id,visitor_id,state,created_at,expires_at,allowed_accounts::text from lab.workspace where visitor_id=?",
                (rs, n) -> new WorkspaceView(rs.getObject("id", UUID.class), rs.getObject("visitor_id", UUID.class),
                        rs.getString("state"),
                        rs.getTimestamp("created_at").toInstant(), rs.getTimestamp("expires_at").toInstant(),
                        Arrays.asList(documents.read(rs.getString("allowed_accounts"), String[].class))), visitorId));
    }
}
