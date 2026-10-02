package io.contexa.demo.platform.observation;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.demo.observation.engine.dto.EngineObservation;
import io.contexa.demo.observation.engine.service.EngineObservationSink;
import io.contexa.demo.observation.learning.dto.LearningSource;
import io.contexa.demo.observation.rag.dto.RagDocumentFingerprint;
import io.contexa.demo.observation.rag.dto.RagWriteObservation;
import io.contexa.demo.observation.rag.service.RagWriteObservationSink;
import io.contexa.demo.platform.observation.support.AbstractNativeDecisionObservationAspect;
import io.contexa.demo.shared.document.DocumentCodec;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.ai.document.Document;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Aspect
@Component
@Profile("contexa")
public class NativeRagWriteObservationAspect extends AbstractNativeDecisionObservationAspect {

    private final ThreadLocal<LearningSource> current = new ThreadLocal<>();
    private final RagWriteObservationSink writes;
    private final EngineObservationSink events;
    private final DocumentCodec documents;

    public NativeRagWriteObservationAspect(RagWriteObservationSink writes,
            EngineObservationSink events, DocumentCodec documents) {
        this.writes = writes;
        this.events = events;
        this.documents = documents;
    }

    @Around("execution(* io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor.storeInVectorDatabase(..))"
            + " && args(event, decision)")
    public Object observeCall(ProceedingJoinPoint invocation, SecurityEvent event, SecurityDecision decision)
            throws Throwable {
        LearningSource previous = current.get();
        LearningSource source = readSafely(() -> source(event == null ? null : event.getUserId(), decision, event));
        restore(source);
        try {
            Object returned = invocation.proceed();
            observeSafely(() -> recordCall(source, null));
            return returned;
        } catch (Throwable failure) {
            observeSafely(() -> recordCall(source, failure.getClass().getSimpleName()));
            throw failure;
        } finally {
            restore(previous);
        }
    }

    @Around("execution(* io.contexa.contexacore.std.rag.service.VectorOperations+.storeDocument(..)) && args(document)")
    public Object observeWrite(ProceedingJoinPoint invocation, Document document) throws Throwable {
        LearningSource source = current.get();
        RagDocumentFingerprint submitted = readSafely(() -> fingerprint(source, document));
        if (submitted == null) {
            return invocation.proceed();
        }
        try {
            Object returned = invocation.proceed();
            observeSafely(() -> recordWrite(source, submitted, null));
            return returned;
        } catch (Throwable failure) {
            observeSafely(() -> recordWrite(source, submitted, failure.getClass().getSimpleName()));
            throw failure;
        }
    }

    private RagDocumentFingerprint fingerprint(LearningSource source, Document document) {
        if (source == null || document == null
                || !Objects.equals(source.eventId(), document.getMetadata().get("eventId"))) {
            return null;
        }
        String content = document.getText();
        byte[] bytes = content != null && content.length() <= 262144
                ? content.getBytes(StandardCharsets.UTF_8) : null;
        Object type = document.getMetadata().get("documentType");
        return new RagDocumentFingerprint(document.getId(), bytes == null ? null : documents.hash(bytes),
                bytes == null ? null : bytes.length, source.eventId(), type instanceof String text ? text : null);
    }

    private void recordWrite(LearningSource source, RagDocumentFingerprint submitted, String failureType) {
        writes.offer(new RagWriteObservation(UUID.randomUUID(), source, Instant.now(), submitted, failureType));
    }

    private void recordCall(LearningSource source, String failureType) {
        if (source == null) {
            return;
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("source", source);
        payload.put("captureBoundary", "NATIVE_POST_PROCESSOR_RETURN");
        payload.put("boundary", "RETURN_VALUE_IS_NOT_STORAGE_ACKNOWLEDGEMENT");
        if (failureType != null) {
            payload.put("failureType", failureType);
        }
        events.offer(new EngineObservation(UUID.randomUUID(), source.requestId(), "RAG_STORAGE_CALL",
                Instant.now(), payload));
    }

    private void restore(LearningSource source) {
        if (source == null) {
            current.remove();
        } else {
            current.set(source);
        }
    }
}
