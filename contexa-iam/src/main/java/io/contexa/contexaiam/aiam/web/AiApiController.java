package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.streaming.StandardStreamingService;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import io.contexa.contexaiam.domain.dto.AiGeneratedPolicyDraftDto;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.CompatibilityResult;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/ai/policies")
@RequiredArgsConstructor
@Slf4j
public class AiApiController {

    private final AICoreOperations<PolicyContext> aiNativeProcessor;
    private final StandardStreamingService streamingService;
    private final ConditionTemplateRepository conditionTemplateRepository;
    private final ManagedResourceRepository managedResourceRepository;
    private final ConditionCompatibilityService conditionCompatibilityService;

    @PostMapping(value = "/generate-from-text/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<String>> generatePolicyFromTextStream(@RequestBody PolicyGenerationItem request) {

        String naturalLanguageQuery = request.naturalLanguageQuery();
        if (naturalLanguageQuery == null || naturalLanguageQuery.trim().isEmpty()) {
            return streamingService.errorStream("VALIDATION_ERROR", "naturalLanguageQuery is required");
        }

        PolicyGenerationRequest aiRequest = createPolicyRequest(request, new TemplateType("PolicyGenerationStreaming"), new DiagnosisType("PolicyGeneration"));
        return streamingService.stream(aiRequest, aiNativeProcessor);
    }

    @PostMapping("/generate-from-text")
    public Mono<ResponseEntity<PolicyResponse>> generatePolicyFromText(@RequestBody PolicyGenerationItem request) {

        String naturalLanguageQuery = request.naturalLanguageQuery();
        if (naturalLanguageQuery == null || naturalLanguageQuery.trim().isEmpty()) {
            return Mono.just(ResponseEntity.badRequest().build());
        }

        PolicyGenerationRequest aiRequest = createPolicyRequest(request, new TemplateType("PolicyGeneration"), new DiagnosisType("PolicyGeneration"));
        return streamingService.process(aiRequest, aiNativeProcessor, PolicyResponse.class)
                .map(body -> {
                    return ResponseEntity.ok(body);
                })
                .onErrorResume(error -> {
                    log.error("Policy generation failed", error);
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build());
                });
    }

    private PolicyGenerationRequest createPolicyRequest(PolicyGenerationItem request,TemplateType templateType, DiagnosisType diagnosisType) {

        PolicyContext context = new PolicyContext.Builder().build();

        PolicyGenerationRequest policyGenerationRequest = new PolicyGenerationRequest(context, templateType, diagnosisType);
        policyGenerationRequest.setNaturalLanguageQuery(request.naturalLanguageQuery());
        policyGenerationRequest.setAvailableItems(request.availableItems());
        policyGenerationRequest.withParameter("availableItems", request.availableItems());

        return policyGenerationRequest;
    }
}