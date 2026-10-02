package io.contexa.demo.observation.engine.repository;

import io.contexa.demo.observation.engine.dto.EngineObservation;

import java.util.List;
import java.util.UUID;

public interface EngineObservationRepository {

    void append(EngineObservation observation);

    List<EngineObservation> find(UUID requestId);
}
