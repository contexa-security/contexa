package io.contexa.demo.observation.rag.service.impl;

import io.contexa.demo.observation.engine.dto.EngineObservation;
import io.contexa.demo.observation.engine.service.EngineObservationSink;
import io.contexa.demo.observation.rag.dto.RagWriteObservation;
import io.contexa.demo.observation.rag.service.RagWriteObservationSink;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import java.util.Map;

@Service
@Profile("contexa")
public class NativeRagWriteObservationSink implements RagWriteObservationSink {

    private final EngineObservationSink observations;

    public NativeRagWriteObservationSink(EngineObservationSink observations) {
        this.observations = observations;
    }

    @Override
    public void offer(RagWriteObservation observation) {
        observations.offer(new EngineObservation(observation.id(), observation.source().requestId(),
                "RAG_WRITE", observation.returnedAt(), Map.of("pendingRead", observation,
                        "captureBoundary", "NATIVE_STORE_DOCUMENT_RETURN_READ_NOT_YET_CAPTURED")));
    }
}
