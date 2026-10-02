package io.contexa.demo.observation.engine.service;

import io.contexa.demo.observation.engine.dto.EngineObservation;

public interface EngineObservationSink {

    void offer(EngineObservation observation);

    long missingCount();
}
