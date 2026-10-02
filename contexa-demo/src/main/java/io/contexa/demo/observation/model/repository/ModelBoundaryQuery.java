package io.contexa.demo.observation.model.repository;

import io.contexa.demo.observation.model.dto.ModelBoundaryEvidence;

import java.util.UUID;

public interface ModelBoundaryQuery {

    ModelBoundaryEvidence find(UUID requestId);
}
