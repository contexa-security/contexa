package io.contexa.demo.observation.request.service;

import io.contexa.demo.observation.request.dto.RequestEvidenceView;

import java.util.UUID;

public interface RequestEvidenceQuery {

    RequestEvidenceView find(UUID requestId, UUID visitorId);
}
