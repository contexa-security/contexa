package io.contexa.demo.observation.rag.service;

import io.contexa.demo.observation.rag.dto.RagWriteObservation;

public interface RagWriteObservationSink {

    void offer(RagWriteObservation observation);
}
