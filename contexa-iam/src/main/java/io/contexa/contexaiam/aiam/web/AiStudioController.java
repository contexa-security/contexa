package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.streaming.StandardStreamingService;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryItem;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryRequest;
import io.contexa.contexaiam.aiam.protocol.response.StudioQueryResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/ai/studio")
@RequiredArgsConstructor
@Slf4j
public class AiStudioController {

    private final AICoreOperations<StudioQueryContext> aiNativeProcessor;
    private final StandardStreamingService streamingService;

    @PostMapping("/query")
    public Mono<ResponseEntity<StudioQueryResponse>> queryStudio(@RequestBody StudioQueryItem request) {

        StudioQueryRequest studioQueryRequest = getStudioQueryRequest(request,  new TemplateType("StudioQuery"), new DiagnosisType("StudioQuery"));

        return streamingService.process(studioQueryRequest, aiNativeProcessor, StudioQueryResponse.class)
                .map(ResponseEntity::ok)
                .onErrorResume(error -> {
                    log.error("AI Studio query failed", error);
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build());
                });
    }

    @PostMapping(value = "/query/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<String>> queryStudioStream(@RequestBody StudioQueryItem request) {

        StudioQueryRequest studioQueryRequest = getStudioQueryRequest(request,  new TemplateType("StudioQueryStreaming"), new DiagnosisType("StudioQuery"));
        
        return streamingService.stream(studioQueryRequest, aiNativeProcessor);
    }

    private StudioQueryRequest getStudioQueryRequest(StudioQueryItem request, TemplateType templateType, DiagnosisType diagnosisType) {
        StudioQueryContext context = new StudioQueryContext.Builder().build();

        StudioQueryRequest studioQueryRequest = new StudioQueryRequest(context, templateType, diagnosisType);
        studioQueryRequest.setNaturalLanguageQuery(request.getQuery());
        return studioQueryRequest;
    }
}