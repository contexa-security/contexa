package io.contexa.demo.observation.request.service;

import io.contexa.demo.observation.request.dto.RequestEvidenceView;

import java.util.UUID;

public interface WorkspaceEvidenceQuery {

    RequestEvidenceView find(String arm, UUID requestId, UUID visitorId);
}
