package io.contexa.demo.workspace.budget.repository.jdbc;

import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import io.contexa.demo.workspace.budget.dto.WorkspaceBudgetKind;
import io.contexa.demo.workspace.budget.repository.WorkspaceBudgetRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;

import java.util.List;
import java.util.UUID;

@Repository
public class JdbcWorkspaceBudgetRepository extends AbstractJdbcRepository implements WorkspaceBudgetRepository {

    private final TransactionOperations transactions;

    public JdbcWorkspaceBudgetRepository(@Qualifier("comparisonJdbc") JdbcOperations jdbc,
            @Qualifier("comparisonTransactions") TransactionOperations transactions) {
        super(jdbc);
        this.transactions = transactions;
    }

    @Override
    public boolean consume(UUID workspaceId, WorkspaceBudgetKind kind, UUID attemptId, UUID sourceId) {
        return Boolean.TRUE.equals(transactions.execute(status -> {
            List<UUID> leases = jdbc.query("""
                    select id from lab.workspace_lease where workspace_id=? and state='ACTIVE'
                        and expires_at>clock_timestamp() for update
                    """, (rs, index) -> rs.getObject("id", UUID.class), workspaceId);
            UUID leaseId = first(leases);
            if (leaseId == null) {
                return false;
            }
            Boolean reused = jdbc.queryForObject("""
                    select exists(select 1 from lab.workspace_budget_attempt where id=? and lease_id=?
                        and kind=? and source_id is not distinct from ?)
                    """, Boolean.class, attemptId, leaseId, kind.name(), sourceId);
            if (Boolean.TRUE.equals(reused)) {
                return true;
            }
            String column = kind.column();
            int changed = jdbc.update("update lab.workspace_lease set " + column + "_used=" + column + "_used+1"
                    + " where id=? and state='ACTIVE' and expires_at>clock_timestamp() and "
                    + column + "_used<" + column + "_limit", leaseId);
            if (changed != 1) {
                return false;
            }
            jdbc.update("insert into lab.workspace_budget_attempt(id,lease_id,kind,source_id) values (?,?,?,?)",
                    attemptId, leaseId, kind.name(), sourceId);
            return true;
        }));
    }
}
