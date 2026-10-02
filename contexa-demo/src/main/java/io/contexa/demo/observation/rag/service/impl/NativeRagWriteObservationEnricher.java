package io.contexa.demo.observation.rag.service.impl;

import io.contexa.demo.observation.engine.dto.EngineObservation;
import io.contexa.demo.observation.engine.service.EngineObservationEnricher;
import io.contexa.demo.observation.rag.dto.RagDocumentReadback;
import io.contexa.demo.observation.rag.dto.RagWriteObservation;
import io.contexa.demo.observation.rag.service.RagDocumentQuery;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
@Profile("contexa")
public class NativeRagWriteObservationEnricher implements EngineObservationEnricher {

    private final ObjectProvider<RagDocumentQuery> documents;

    public NativeRagWriteObservationEnricher(ObjectProvider<RagDocumentQuery> documents) {
        this.documents = documents;
    }

    @Override
    public EngineObservation enrich(EngineObservation observation) {
        if (!"RAG_WRITE".equals(observation.kind())
                || !(observation.payload().get("pendingRead") instanceof RagWriteObservation write)) {
            return observation;
        }
        RagDocumentReadback readback = read(write);
        boolean same = write.submitted().contentSha256() != null
                && write.submitted().equals(readback.document());
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("source", write.source());
        payload.put("submitted", write.submitted());
        payload.put("readback", readback);
        payload.put("matchingDocumentObserved", same);
        payload.put("captureBoundary", "NATIVE_STORE_DOCUMENT_RETURN_THEN_QUEUED_READ_BY_DOCUMENT_ID");
        payload.put("boundary", "CONTENT_EVENT_TYPE_MATCH_NOT_FULL_METADATA_OR_DURABILITY_PROOF");
        if (write.failureType() != null) {
            payload.put("failureType", write.failureType());
        }
        return new EngineObservation(observation.id(), observation.requestId(), observation.kind(),
                observation.observedAt(), payload);
    }

    private RagDocumentReadback read(RagWriteObservation write) {
        try {
            return documents.getObject().read(write.submitted().documentId());
        } catch (RuntimeException unavailable) {
            return new RagDocumentReadback("UNAVAILABLE", Instant.now(), null, null, null);
        }
    }
}
