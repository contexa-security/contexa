package io.contexa.demo.workspace.evidence.repository;

import io.contexa.demo.workspace.evidence.dto.WorkspaceEvidenceStores;

import java.util.UUID;

public interface WorkspaceEvidenceStoreRepository {

    void bind(UUID leaseId, WorkspaceEvidenceStores stores);

    WorkspaceEvidenceStores find(UUID visitorId);
}
