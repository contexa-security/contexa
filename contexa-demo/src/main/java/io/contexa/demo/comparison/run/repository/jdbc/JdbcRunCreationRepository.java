package io.contexa.demo.comparison.run.repository.jdbc;

import io.contexa.demo.comparison.run.dto.RunRecord;
import io.contexa.demo.comparison.run.repository.RunCreationRepository;
import io.contexa.demo.comparison.run.repository.RunQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import io.contexa.demo.workspace.budget.dto.WorkspaceBudgetKind;
import io.contexa.demo.workspace.budget.service.WorkspaceBudgetService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.web.server.ResponseStatusException;
import java.sql.Timestamp;
import java.util.List;
import java.util.UUID;

@Repository
public class JdbcRunCreationRepository extends AbstractJsonJdbcRepository implements RunCreationRepository {

    private final TransactionOperations transactions;
    private final RunQuery query;
    private final WorkspaceBudgetService budgets;

    public JdbcRunCreationRepository(@Qualifier("comparisonJdbc") JdbcOperations jdbc, DocumentCodec documents,
            @Qualifier("comparisonTransactions") TransactionOperations transactions, RunQuery query,
            WorkspaceBudgetService budgets) {
        super(jdbc, documents);
        this.transactions = transactions;
        this.query = query;
        this.budgets = budgets;
    }

    @Override
    public RunRecord save(RunRecord candidate) {
        RunRecord stored = transactions.execute(status -> {
            Boolean active = jdbc.queryForObject("""
                    select exists(select 1 from lab.workspace where id=? and visitor_id=?
                        and expires_at>clock_timestamp())
                    """, Boolean.class, candidate.workspaceId(), candidate.visitorId());
            if (!Boolean.TRUE.equals(active)) {
                throw new ResponseStatusException(HttpStatus.GONE, "WORKSPACE_EXPIRED");
            }
            int inserted = jdbc.update("""
                    insert into lab.comparison_run(id,visitor_id,workspace_id,command_id,coordinator_instance_id,
                        created_at,dispatch_deadline,input_sha256,manifest_sha256,manifest,state)
                    values (?,?,?,?,?,?,?,?,?,cast(? as jsonb),'READY')
                    on conflict(visitor_id,command_id) do nothing
                    """, candidate.id(), candidate.visitorId(), candidate.workspaceId(), candidate.commandId(),
                    candidate.coordinatorInstanceId(), Timestamp.from(candidate.createdAt()),
                    Timestamp.from(candidate.dispatchDeadline()), candidate.inputSha256(), candidate.manifestSha256(),
                    documents.write(candidate.manifest()));
            if (inserted == 1) {
                budgets.require(candidate.workspaceId(), WorkspaceBudgetKind.COMPARISON, candidate.id(), candidate.id());
                for (String arm : List.of("baseline", "contexa")) {
                    jdbc.update("""
                            insert into lab.comparison_run_step(id,run_id,arm,ordinal,state)
                            values (?,?,?,1,'PLANNED')
                            """, UUID.randomUUID(), candidate.id(), arm);
                }
                jdbc.update("insert into lab.comparison_run_event(run_id,kind,detail) values (?,'CREATED',?)",
                        candidate.id(), candidate.manifestSha256());
            }
            return recordAttempt(candidate.visitorId(), candidate.commandId(), candidate.inputSha256(),
                    inserted == 1 ? "CREATED" : "REUSED");
        });
        return requireSame(stored, candidate.inputSha256());
    }

    @Override
    public RunRecord reuse(UUID visitorId, UUID commandId, String inputSha256) {
        RunRecord stored = transactions.execute(status -> recordAttempt(visitorId, commandId, inputSha256, "REUSED"));
        return requireSame(stored, inputSha256);
    }

    private RunRecord recordAttempt(UUID visitorId, UUID commandId, String hash, String outcome) {
        RunRecord stored = query.findCommand(visitorId, commandId);
        if (stored == null) {
            return null;
        }
        jdbc.update("""
                insert into lab.comparison_run_creation_attempt(run_id,submitted_input_sha256,outcome)
                values (?,?,?)
                """, stored.id(), hash, stored.inputSha256().equals(hash) ? outcome : "INPUT_CONFLICT");
        return stored;
    }

    private RunRecord requireSame(RunRecord stored, String hash) {
        if (stored == null || !stored.inputSha256().equals(hash)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "COMMAND_INPUT_CHANGED");
        }
        return stored;
    }
}
