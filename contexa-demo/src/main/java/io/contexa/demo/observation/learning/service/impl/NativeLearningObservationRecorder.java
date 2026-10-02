package io.contexa.demo.observation.learning.service.impl;

import io.contexa.demo.observation.engine.dto.EngineObservation;
import io.contexa.demo.observation.engine.service.EngineObservationSink;
import io.contexa.demo.observation.learning.dto.BaselineValueSnapshot;
import io.contexa.demo.observation.learning.dto.LearningSource;
import io.contexa.demo.observation.learning.service.LearningObservationRecorder;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Service
@Profile("contexa")
public class NativeLearningObservationRecorder implements LearningObservationRecorder {

    private final EngineObservationSink sink;

    public NativeLearningObservationRecorder(EngineObservationSink sink) {
        this.sink = sink;
    }

    @Override
    public void callReturned(LearningSource source, Boolean returned, String failureType) {
        if (source == null) {
            return;
        }
        Map<String, Object> payload = payload(source, "NATIVE_LEARN_IF_NORMAL_RETURN", failureType);
        if (returned != null) {
            payload.put("returned", returned);
        }
        payload.put("boundary", "RETURN_VALUE_IS_NOT_STORAGE_ACKNOWLEDGEMENT");
        record(source, "BASELINE_LEARNING_CALL", payload);
    }

    @Override
    public void writeReturned(LearningSource source, BaselineValueSnapshot submitted,
            BaselineValueSnapshot observed, String failureType) {
        if (source == null) {
            return;
        }
        Map<String, Object> payload = payload(source, "NATIVE_SAVE_USER_BASELINE_RETURN_AND_READ", failureType);
        if (submitted != null) {
            payload.put("submitted", submitted);
        }
        if (observed != null) {
            payload.put("observed", observed);
        }
        payload.put("sameValueObserved", submitted != null && observed != null && submitted.sha256() != null
                && submitted.sha256().equals(observed.sha256()));
        payload.put("boundary", "READ_AFTER_THIS_NATIVE_WRITE_NOT_DURABILITY_OR_EXCLUSIVE_CAUSALITY_PROOF");
        record(source, "BASELINE_WRITE", payload);
    }

    private Map<String, Object> payload(LearningSource source, String boundary, String failureType) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("source", source);
        payload.put("captureBoundary", boundary);
        if (failureType != null) {
            payload.put("failureType", failureType);
        }
        return payload;
    }

    private void record(LearningSource source, String kind, Map<String, Object> payload) {
        sink.offer(new EngineObservation(UUID.randomUUID(), source.requestId(), kind, Instant.now(), payload));
    }
}
