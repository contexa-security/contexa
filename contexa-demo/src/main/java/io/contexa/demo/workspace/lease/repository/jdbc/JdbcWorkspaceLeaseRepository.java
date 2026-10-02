package io.contexa.demo.workspace.lease.repository.jdbc;

import io.contexa.demo.workspace.configuration.WorkspaceAccessProperties;
import io.contexa.demo.workspace.dto.WorkspaceView;
import io.contexa.demo.workspace.lease.dto.WorkspaceLease;
import io.contexa.demo.workspace.lease.repository.WorkspaceLeaseRepository;
import io.contexa.demo.observation.configuration.EvidenceStoreProperties;
import io.contexa.demo.workspace.evidence.dto.WorkspaceEvidenceStores;
import io.contexa.demo.workspace.evidence.repository.WorkspaceEvidenceStoreRepository;
import io.contexa.demo.workspace.lifecycle.repository.WorkspaceRunRetirementRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@Repository
public class JdbcWorkspaceLeaseRepository extends AbstractLeaseJdbcRepository implements WorkspaceLeaseRepository {

    private final TransactionOperations transactions;
    private final WorkspaceAccessProperties properties;
    private final WorkspaceEvidenceStoreRepository stores;
    private final EvidenceStoreProperties evidence;
    private final WorkspaceRunRetirementRepository runs;

    public JdbcWorkspaceLeaseRepository(@Qualifier("comparisonJdbc") JdbcOperations jdbc,
            @Qualifier("comparisonTransactions") TransactionOperations transactions,
            WorkspaceAccessProperties properties, WorkspaceEvidenceStoreRepository stores, EvidenceStoreProperties evidence,
            WorkspaceRunRetirementRepository runs) {
        super(jdbc);
        this.transactions = transactions;
        this.properties = properties;
        this.stores = stores;
        this.evidence = evidence;
        this.runs = runs;
    }

    @Override
    public WorkspaceLease acquire(WorkspaceView workspace) {
        return transactions.execute(status -> {
            jdbc.queryForObject("select id from lab.workspace where id=? and visitor_id=? for update",
                    UUID.class, workspace.id(), workspace.visitorId());
            WorkspaceLease previous = lease("where l.workspace_id=?", workspace.id());
            if (previous != null) {
                return previous;
            }
            String slot = first(jdbc.query("""
                    select s.id from lab.workspace_slot s where s.state='AVAILABLE'
                        and (select count(*) from lab.workspace_slot_worker w where w.slot_id=s.id
                            and w.generation=s.generation and w.registered_at>clock_timestamp()-interval '15 seconds')=2
                    order by s.id limit 1 for update of s skip locked
                    """, (rs, index) -> rs.getString("id")));
            if (slot == null) {
                throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "WORKSPACE_CAPACITY_UNAVAILABLE");
            }
            UUID id = UUID.randomUUID();
            int inserted = jdbc.update("""
                    with lease_clock as materialized (select clock_timestamp() as started_at)
                    insert into lab.workspace_lease(id,workspace_id,visitor_id,slot_id,generation,baseline_url,contexa_url,created_at,expires_at,
                        comparison_limit,chat_limit,embedding_limit,work_limit)
                    select ?,w.id,w.visitor_id,s.id,s.generation,s.baseline_url,s.contexa_url,c.started_at,
                        least(w.expires_at,c.started_at+(? * interval '1 millisecond')),?,?,?,?
                    from lab.workspace w cross join lab.workspace_slot s cross join lease_clock c
                    where w.id=? and s.id=? and w.expires_at>c.started_at
                    """, id, properties.lifetime().toMillis(), properties.comparisons(), properties.chatTransmissions(),
                    properties.embeddingTransmissions(), properties.workRequests(), workspace.id(), slot);
            if (inserted != 1) {
                throw new ResponseStatusException(HttpStatus.GONE, "WORKSPACE_EXPIRED");
            }
            stores.bind(id, new WorkspaceEvidenceStores(evidence.baselineUrl(), evidence.contexaUrl(), evidence.securityUrl()));
            jdbc.update("update lab.workspace_slot set state='LEASED',updated_at=clock_timestamp() where id=?", slot);
            jdbc.update("""
                    update lab.workspace set state='ACTIVE',expires_at=(select expires_at from lab.workspace_lease where id=?)
                    where id=?
                    """, id, workspace.id());
            return lease("where l.id=?", id);
        });
    }

    @Override
    public WorkspaceLease find(UUID visitorId) {
        return lease("where l.visitor_id=? order by l.created_at desc,l.id desc limit 1", visitorId);
    }

    @Override
    public WorkspaceLease findWorker(String slotId, UUID generation) {
        return lease("where l.slot_id=? and l.generation=? and l.state='ACTIVE' and l.expires_at>clock_timestamp()",
                slotId, generation);
    }

    @Override
    public int expire() {
        return transactions.execute(status -> {
            WorkspaceLease expired = lease("where l.state='ACTIVE' and l.expires_at<=clock_timestamp() for update skip locked");
            if (expired == null) {
                runs.retireClosedWorkspaces();
                return 0;
            }
            jdbc.update("update lab.workspace_lease set state='EXPIRED' where id=?", expired.id());
            jdbc.update("update lab.workspace set state='EXPIRED' where id=?", expired.workspaceId());
            jdbc.update("""
                    update lab.workspace_slot set state='RESET_REQUIRED',updated_at=clock_timestamp()
                    where id=? and generation=?
                    """, expired.slotId(), expired.generation());
            runs.retireClosedWorkspaces();
            return 1;
        });
    }

    @Override
    public WorkspaceLease cancel(UUID visitorId) {
        return transactions.execute(status -> {
            WorkspaceLease lease = lease("where l.visitor_id=? for update", visitorId);
            if (lease == null) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "WORKSPACE_NOT_ASSIGNED");
            }
            if ("ACTIVE".equals(lease.state())) {
                jdbc.update("update lab.workspace_lease set state='CANCELLED' where id=?", lease.id());
                jdbc.update("update lab.workspace set state='CANCELLED' where id=?", lease.workspaceId());
                jdbc.update("""
                        update lab.workspace_slot set state='RESET_REQUIRED',updated_at=clock_timestamp()
                        where id=? and generation=?
                        """, lease.slotId(), lease.generation());
            }
            runs.retireClosedWorkspaces();
            return lease("where l.id=?", lease.id());
        });
    }
}
