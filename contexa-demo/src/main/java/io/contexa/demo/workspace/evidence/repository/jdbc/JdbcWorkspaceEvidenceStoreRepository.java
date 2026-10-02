package io.contexa.demo.workspace.evidence.repository.jdbc;

import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import io.contexa.demo.workspace.evidence.dto.WorkspaceEvidenceStores;
import io.contexa.demo.workspace.evidence.repository.WorkspaceEvidenceStoreRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public class JdbcWorkspaceEvidenceStoreRepository extends AbstractJdbcRepository implements WorkspaceEvidenceStoreRepository {

    public JdbcWorkspaceEvidenceStoreRepository(@Qualifier("comparisonJdbc") JdbcOperations jdbc) {
        super(jdbc);
    }

    @Override
    public void bind(UUID leaseId, WorkspaceEvidenceStores stores) {
        jdbc.update("""
                insert into lab.workspace_evidence_store(lease_id,baseline_url,contexa_url,security_url)
                values (?,?,?,?) on conflict(lease_id) do nothing
                """, leaseId, stores.baseline(), stores.contexa(), stores.security());
    }

    @Override
    public WorkspaceEvidenceStores find(UUID visitorId) {
        return first(jdbc.query("""
                select s.baseline_url,s.contexa_url,s.security_url from lab.workspace_evidence_store s
                join lab.workspace_lease l on l.id=s.lease_id where l.visitor_id=?
                """, (rs, index) -> new WorkspaceEvidenceStores(rs.getString("baseline_url"),
                        rs.getString("contexa_url"), rs.getString("security_url")), visitorId));
    }
}
