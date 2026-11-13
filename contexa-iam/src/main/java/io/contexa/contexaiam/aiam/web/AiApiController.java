/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacore.exception.StrategicOperationConflictException;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.pipeline.PipelineFailurePolicy;
import io.contexa.contexacore.std.streaming.StandardStreamingService;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.access.prepost.PreAuthorize;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.ConnectException;
import java.net.UnknownHostException;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.TimeoutException;

@RestController
@RequestMapping("/contexa/admin/api/ai/policies")
@RequiredArgsConstructor
@Slf4j
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AiApiController {

    private final AICoreOperations<PolicyContext> aiNativeProcessor;
    private final StandardStreamingService streamingService;

    @PostMapping(value = "/generate/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<String>> generatePolicyFromTextStream(@RequestBody PolicyGenerationItem request) {

        String naturalLanguageQuery = request.naturalLanguageQuery();
        if (naturalLanguageQuery == null || naturalLanguageQuery.trim().isEmpty()) {
            return streamingService.errorStream("VALIDATION_ERROR", "naturalLanguageQuery is required");
        }

        PolicyGenerationRequest aiRequest = createPolicyRequest(request, new TemplateType("PolicyGenerationStreaming"), new DiagnosisType("PolicyGeneration"));
        return streamingService.stream(aiRequest, aiNativeProcessor);
    }

    /** The model server cannot be reached (connection refused, unknown host). */
    public static final String MODEL_UNREACHABLE = "AI_MODEL_UNREACHABLE";
    /** The model did not answer in time. */
    public static final String MODEL_TIMEOUT = "AI_MODEL_TIMEOUT";
    /** The model answered, but with no policy. */
    public static final String NO_POLICY = "AI_NO_POLICY_GENERATED";
    /** Any other failure of the generation. */
    public static final String GENERATION_FAILED = "AI_GENERATION_FAILED";

    /**
     * What the caller receives for a generated policy: the policy, the names of the ids it uses, the model's reasoning,
     * and the server time of the answer. The prompt and model details the pipeline records stay on the server.
     */
    public record GeneratedPolicy(BusinessPolicyDto policyData, Map<String, String> roleIdToNameMap,
                                  Map<String, String> permissionIdToNameMap, Map<String, String> conditionIdToNameMap,
                                  String reasoning, LocalDateTime timestamp) {
    }

    /**
     * Generates a policy. A failed generation answers with an error status and the reason (model unreachable, timed
     * out, no policy in the answer), never with a 200 carrying a synthetic response.
     */
    @PostMapping("/generate")
    public Mono<ResponseEntity<Object>> generatePolicyFromText(@RequestBody PolicyGenerationItem request) {

        String naturalLanguageQuery = request.naturalLanguageQuery();
        if (naturalLanguageQuery == null || naturalLanguageQuery.trim().isEmpty()) {
            return Mono.just(ResponseEntity.badRequest().build());
        }

        PolicyGenerationRequest aiRequest = createPolicyRequest(request, new TemplateType("PolicyGeneration"), new DiagnosisType("PolicyGeneration"));
        aiRequest.withParameter("pipelineFailurePolicy", PipelineFailurePolicy.PROPAGATE_ERROR.name());
        return streamingService.process(aiRequest, aiNativeProcessor, PolicyResponse.class)
                .map(this::answer)
                .switchIfEmpty(Mono.fromSupplier(() -> failure(HttpStatus.BAD_GATEWAY, NO_POLICY,
                        "The model returned no answer.")))
                .onErrorResume(error -> Mono.just(failure(error)));
    }

    private ResponseEntity<Object> answer(PolicyResponse response) {
        if (response.getErrorMessage() != null && !response.getErrorMessage().isBlank()) {
            log.error("Policy generation failed: {}", response.getErrorMessage());
            return failure(HttpStatus.INTERNAL_SERVER_ERROR, GENERATION_FAILED, "The policy could not be generated.");
        }
        if (response.getPolicyData() == null) {
            log.warn("Policy generation answered without a policy");
            return failure(HttpStatus.UNPROCESSABLE_ENTITY, NO_POLICY,
                    "The model answered without a policy. Rephrase the request or check the available items.");
        }
        return ResponseEntity.ok(new GeneratedPolicy(response.getPolicyData(), response.getRoleIdToNameMap(),
                response.getPermissionIdToNameMap(), response.getConditionIdToNameMap(), response.getReasoning(),
                LocalDateTime.now()));
    }

    private ResponseEntity<Object> failure(Throwable error) {
        if (error instanceof StrategicOperationConflictException) {
            log.warn("Policy generation refused: an identical request is already running");
            return failure(HttpStatus.CONFLICT, "AI_GENERATION_RUNNING", "An identical request is already running.");
        }
        log.error("Policy generation failed", error);
        if (causedBy(error, TimeoutException.class)) {
            return failure(HttpStatus.GATEWAY_TIMEOUT, MODEL_TIMEOUT, "The AI model did not answer in time.");
        }
        if (causedBy(error, ConnectException.class) || causedBy(error, UnknownHostException.class)) {
            return failure(HttpStatus.SERVICE_UNAVAILABLE, MODEL_UNREACHABLE, "The AI model server cannot be reached.");
        }
        return failure(HttpStatus.INTERNAL_SERVER_ERROR, GENERATION_FAILED, "The policy could not be generated.");
    }

    private static ResponseEntity<Object> failure(HttpStatus status, String code, String message) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, message);
        problem.setProperty("code", code);
        return ResponseEntity.status(status).body(problem);
    }

    private static boolean causedBy(Throwable error, Class<? extends Throwable> type) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            if (type.isInstance(current)) {
                return true;
            }
            if (current.getCause() == current) {
                return false;
            }
        }
        return false;
    }

    private PolicyGenerationRequest createPolicyRequest(PolicyGenerationItem request,TemplateType templateType, DiagnosisType diagnosisType) {

        PolicyContext context = new PolicyContext.Builder().build();
        PolicyGenerationRequest policyGenerationRequest = new PolicyGenerationRequest(context, templateType, diagnosisType);
        policyGenerationRequest.setNaturalLanguageQuery(request.naturalLanguageQuery());
        policyGenerationRequest.withParameter("naturalLanguageQuery", request.naturalLanguageQuery());
        policyGenerationRequest.setAvailableItems(request.availableItems());
        if (request.availableItems() != null) {
            policyGenerationRequest.withParameter("availableItems", request.availableItems());
        }

        return policyGenerationRequest;
    }
}