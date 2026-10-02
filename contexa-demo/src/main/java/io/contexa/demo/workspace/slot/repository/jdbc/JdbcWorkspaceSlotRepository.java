package io.contexa.demo.workspace.slot.repository.jdbc;

import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import io.contexa.demo.workspace.configuration.WorkspaceSlotDefinition;
import io.contexa.demo.workspace.slot.repository.WorkspaceSlotRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;

import java.util.Set;
import java.util.UUID;

@Repository
public class JdbcWorkspaceSlotRepository extends AbstractJdbcRepository implements WorkspaceSlotRepository {

    private final TransactionOperations transactions;

    public JdbcWorkspaceSlotRepository(@Qualifier("comparisonJdbc") JdbcOperations jdbc,
            @Qualifier("comparisonTransactions") TransactionOperations transactions) {
        super(jdbc);
        this.transactions = transactions;
    }

    @Override
    public void configure(WorkspaceSlotDefinition slot) {
        int changed = jdbc.update("""
                insert into lab.workspace_slot(id,generation,baseline_url,contexa_url) values (?,?,?,?)
                on conflict(id) do update set generation=excluded.generation,baseline_url=excluded.baseline_url,
                    contexa_url=excluded.contexa_url,state=case when workspace_slot.generation=excluded.generation
                        then workspace_slot.state else 'PREPARING' end,updated_at=clock_timestamp()
                where workspace_slot.state<>'LEASED' or (workspace_slot.generation=excluded.generation
                    and workspace_slot.baseline_url=excluded.baseline_url and workspace_slot.contexa_url=excluded.contexa_url)
                """, slot.id(), slot.generation(), slot.baseline().toString(), slot.contexa().toString());
        if (changed != 1) {
            throw new IllegalStateException("An active workspace slot cannot change generation or endpoints");
        }
    }

    @Override
    public void registerWorker(String slotId, UUID generation, String arm, UUID instanceId) {
        if (!Set.of("baseline", "contexa").contains(arm)) {
            throw new IllegalArgumentException("Invalid workspace worker role");
        }
        transactions.executeWithoutResult(status -> {
            Boolean configured = jdbc.queryForObject("""
                    select exists(select 1 from lab.workspace_slot where id=? and generation=?)
                    """, Boolean.class, slotId, generation);
            if (!Boolean.TRUE.equals(configured)) {
                throw new IllegalStateException("Workspace worker generation is not in the configured catalog");
            }
            jdbc.update("""
                    insert into lab.workspace_slot_worker(slot_id,generation,arm,instance_id) values (?,?,?,?)
                    on conflict(slot_id,generation,arm) do update set instance_id=excluded.instance_id,
                        registered_at=clock_timestamp()
                    """, slotId, generation, arm, instanceId);
            jdbc.update("""
                    update lab.workspace_slot s set state='AVAILABLE',updated_at=clock_timestamp()
                    where s.id=? and s.generation=? and s.state='PREPARING'
                        and (select count(*) from lab.workspace_slot_worker w
                            where w.slot_id=s.id and w.generation=s.generation)=2
                    """, slotId, generation);
        });
    }

    @Override
    public void heartbeat(String slotId, UUID generation, String arm, UUID instanceId) {
        jdbc.update("""
                update lab.workspace_slot_worker set registered_at=clock_timestamp()
                where slot_id=? and generation=? and arm=? and instance_id=?
                """, slotId, generation, arm, instanceId);
    }
}
