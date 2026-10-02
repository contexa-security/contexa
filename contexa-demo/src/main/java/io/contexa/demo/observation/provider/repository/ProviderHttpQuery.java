package io.contexa.demo.observation.provider.repository;

import io.contexa.demo.observation.provider.dto.ProviderHttpEvidence;

import java.util.UUID;

public interface ProviderHttpQuery {

    ProviderHttpEvidence find(UUID requestId);
}
