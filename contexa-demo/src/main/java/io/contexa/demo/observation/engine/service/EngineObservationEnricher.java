package io.contexa.demo.observation.engine.service;

import io.contexa.demo.observation.engine.dto.EngineObservation;

public interface EngineObservationEnricher {

    EngineObservation enrich(EngineObservation observation);
}
