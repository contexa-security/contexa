package io.contexa.demo.workspace.lease.repository.jdbc;

import io.contexa.demo.configuration.properties.LabEndpoints;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import io.contexa.demo.workspace.lease.dto.WorkspaceLease;
import io.contexa.demo.workspace.lease.dto.WorkspaceUsage;
import org.springframework.jdbc.core.JdbcOperations;

import java.net.URI;
import java.util.UUID;

public abstract class AbstractLeaseJdbcRepository extends AbstractJdbcRepository {

    protected static final String LEASE_COLUMNS = """
            select l.* from lab.workspace_lease l
            """;

    protected AbstractLeaseJdbcRepository(JdbcOperations jdbc) {
        super(jdbc);
    }

    protected WorkspaceLease lease(String suffix, Object... arguments) {
        return first(jdbc.query(LEASE_COLUMNS + suffix, (rs, index) -> new WorkspaceLease(
                rs.getObject("id", UUID.class), rs.getObject("workspace_id", UUID.class),
                rs.getObject("visitor_id", UUID.class), rs.getString("slot_id"),
                rs.getObject("generation", UUID.class), rs.getString("state"),
                rs.getTimestamp("created_at").toInstant(), rs.getTimestamp("expires_at").toInstant(),
                new LabEndpoints(URI.create(rs.getString("baseline_url")), URI.create(rs.getString("contexa_url"))),
                new WorkspaceUsage(rs.getInt("comparison_used"), rs.getInt("comparison_limit"),
                        rs.getInt("chat_used"), rs.getInt("chat_limit"), rs.getInt("embedding_used"),
                        rs.getInt("embedding_limit"), rs.getInt("work_used"), rs.getInt("work_limit"))), arguments));
    }
}
