package io.contexa.demo.platform.observation;

import io.contexa.contexacore.std.advisor.core.BaseAdvisor;
import io.contexa.contexacore.std.llm.observation.LlmObservationContext;
import io.contexa.contexacore.util.SensitiveValueSanitizer;
import io.contexa.demo.observation.model.call.ModelCallContext;
import io.contexa.demo.observation.model.call.ModelCallReference;
import io.contexa.demo.observation.model.call.ModelCallScope;
import io.contexa.demo.observation.model.dto.ModelBoundaryObservation;
import io.contexa.demo.observation.model.service.ModelBoundarySink;
import io.contexa.demo.shared.document.DocumentCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.ai.chat.client.advisor.api.CallAdvisorChain;
import org.springframework.ai.chat.client.advisor.api.StreamAdvisorChain;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.time.Instant;
import java.util.UUID;

@Component
@Profile("contexa")
public class ModelBoundaryObservationAdvisor extends BaseAdvisor {

    private static final Logger log = LoggerFactory.getLogger(ModelBoundaryObservationAdvisor.class);
    private final ModelBoundarySink sink;
    private final DocumentCodec documents;
    private final ModelCallContext calls;

    public ModelBoundaryObservationAdvisor(ModelBoundarySink sink, DocumentCodec documents, ModelCallContext calls) {
        super("lab-observation", "model-boundary", Integer.MAX_VALUE - 100);
        this.sink = sink;
        this.documents = documents;
        this.calls = calls;
    }

    @Override
    public ChatClientResponse adviseCall(ChatClientRequest request, CallAdvisorChain chain) {
        Instant startedAt = Instant.now();
        UUID observationId = UUID.randomUUID();
        ModelCallScope scope = openScope(request, observationId);
        ChatClientResponse result = null;
        String failureType = null;
        try {
            result = chain.nextCall(request);
            return result;
        } catch (RuntimeException failure) {
            failureType = failure.getClass().getSimpleName();
            throw failure;
        } finally {
            try {
                capture(request, result, startedAt, failureType, observationId);
            } catch (RuntimeException unavailable) {
                log.warn("Model boundary observation missing: {}", unavailable.getClass().getSimpleName());
            } finally {
                if (scope != null) {
                    try {
                        scope.close();
                    } catch (RuntimeException unavailable) {
                        log.warn("Model observation scope could not close: {}",
                                unavailable.getClass().getSimpleName());
                    }
                }
            }
        }
    }

    private ModelCallScope openScope(ChatClientRequest request, UUID observationId) {
        try {
            Object source = request.context().get(LlmObservationContext.CONTEXT_KEY);
            return calls.open(new ModelCallReference(observationId,
                    source instanceof LlmObservationContext linked ? linked : null));
        } catch (RuntimeException unavailable) {
            log.warn("Model call scope missing: {}", unavailable.getClass().getSimpleName());
            return null;
        }
    }

    private void capture(ChatClientRequest request, ChatClientResponse result, Instant startedAt, String failureType,
            UUID observationId) {
        ChatResponse response = result == null ? null : result.chatResponse();
        String output = response == null || response.getResult() == null ? null : response.getResult().getOutput().getText();
        String safe = output == null ? null : SensitiveValueSanitizer.sanitizeText(output)
                .replaceAll("\\b[A-Fa-f0-9]{32}\\b", "[REDACTED_SESSION_ID]");
        var metadata = response == null ? null : response.getMetadata();
        var usage = metadata == null ? null : metadata.getUsage();
        Object source = request.context().get(LlmObservationContext.CONTEXT_KEY);
        LlmObservationContext observationSource = source instanceof LlmObservationContext linked ? linked : null;
        sink.offer(new ModelBoundaryObservation(observationId, documents.hash(request.prompt().getContents()),
                safe == null ? null : safe.substring(0, Math.min(safe.length(), 65536)),
                safe != null && safe.length() > 65536, metadata == null ? null : metadata.getModel(),
                usage == null ? null : usage.getPromptTokens(), usage == null ? null : usage.getCompletionTokens(),
                startedAt, Instant.now(), failureType, observationSource));
    }

    @Override
    public Flux<ChatClientResponse> adviseStream(ChatClientRequest request, StreamAdvisorChain chain) {
        return chain.nextStream(request);
    }

    @Override
    protected ChatClientRequest beforeCall(ChatClientRequest request) {
        return request;
    }

    @Override
    protected ChatClientResponse afterCall(ChatClientResponse response, ChatClientRequest request) {
        return response;
    }
}
