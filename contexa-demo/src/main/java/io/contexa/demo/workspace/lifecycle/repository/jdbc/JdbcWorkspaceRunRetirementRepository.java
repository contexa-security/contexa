package io.contexa.demo.workspace.lifecycle.repository.jdbc;

import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import io.contexa.demo.workspace.lifecycle.repository.WorkspaceRunRetirementRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public class JdbcWorkspaceRunRetirementRepository extends AbstractJdbcRepository implements WorkspaceRunRetirementRepository {

    public JdbcWorkspaceRunRetirementRepository(@Qualifier("comparisonJdbc") JdbcOperations jdbc) {
        super(jdbc);
    }

    @Override
    public int retireClosedWorkspaces() {
        var ended = jdbc.query("""
                update lab.comparison_run r set state=case when l.state='CANCELLED' then 'CANCELLED' else 'EXPIRED' end
                from lab.workspace_lease l where l.workspace_id=r.workspace_id and l.visitor_id=r.visitor_id
                    and l.state in ('EXPIRED','CANCELLED') and r.state in ('READY','RUNNING')
                returning r.id,r.state
                """, (rs, index) -> {
            UUID id = rs.getObject("id", UUID.class);
            String state = rs.getString("state");
            jdbc.update("update lab.comparison_run_step set state='NOT_DISPATCHED' where run_id=? and state='PLANNED'", id);
            jdbc.update("""
                    insert into lab.comparison_run_event(run_id,kind,detail) values (?,?,?)
                    """, id, "WORKSPACE_" + state, "Workspace ended; undispatched work was not performed");
            return id;
        });
        return ended.size();
    }
}
