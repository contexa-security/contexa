package io.contexa.contexaiam.admin.web.customllm.controller;

import io.contexa.contexacommon.domain.request.IAMRequest;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexacommon.enums.SecurityLevel;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.pipeline.streaming.StreamingContext;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProperties;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Custom LLM Streaming Controller
 * Demonstrates minimal implementation using refactored Contexa streaming modules.
 *
 * Server-side: ~50 lines (including imports)
 * Client-side: ~10 lines JavaScript
 */
@Controller
@RequestMapping("/admin/custom-llm")
@RequiredArgsConstructor
public class CustomLLMController {

    private final AICoreOperations<StudioQueryContext> aiProcessor;
    private final StreamingProperties streamingProperties;

    @GetMapping
    public String customLLMPage(Model model) {
        model.addAttribute("activePage", "custom-llm");
        return "admin/custom-llm";
    }

    @PostMapping(value = "/api/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @ResponseBody
    public Flux<ServerSentEvent<String>> streamLLM(@RequestBody Map<String, String> request) {
        String query = request.get("query");

        StudioQueryContext context = new StudioQueryContext.Builder(
                SecurityLevel.STANDARD, AuditRequirement.BASIC)
                .withNaturalLanguageQuery(query)
                .build();

        IAMRequest<StudioQueryContext> iamRequest = new IAMRequest<>(context, "customLLMStream");
        iamRequest.withDiagnosisType(DiagnosisType.STUDIO_QUERY)
                .withParameter("naturalLanguageQuery", query)
                .withParameter("processingMode", "streaming");

        StreamingContext ctx = new StreamingContext(streamingProperties);

        return aiProcessor.processStream(iamRequest)
            .flatMap(chunk -> {
                ctx.appendChunk(chunk);
                if (ctx.isFinalResponseStarted()) {
                    return Flux.empty();
                }
                return ctx.getSentenceBuffer().processChunk(chunk)
                    .map(sentence -> ServerSentEvent.<String>builder().data(sentence).build());
            })
            .concatWith(Mono.defer(() -> {
                String json = ctx.extractJsonPart();
                if (json != null && !ctx.isJsonSent()) {
                    ctx.markJsonSent();
                    String marker = streamingProperties.getFinalResponseMarker();
                    return Mono.just(ServerSentEvent.<String>builder().data(marker + json).build());
                }
                return Mono.empty();
            }))
            .concatWith(Mono.just(ServerSentEvent.<String>builder().data("[DONE]").build()));
    }
}
