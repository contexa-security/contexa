package io.contexa.contexaiam.aiam.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.streaming.StandardStreamingService;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.client.ResourceAccessException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.ConnectException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * IAM-D59 and IAM-D62: the policy generation API answers a failed generation with an error status and its reason,
 * and a generated policy with the server time and without the prompt and model details the pipeline records.
 */
class AiApiControllerTest {

    @SuppressWarnings("unchecked")
    private final AICoreOperations<PolicyContext> processor = mock(AICoreOperations.class);
    private final StandardStreamingService streaming = mock(StandardStreamingService.class);
    private final AiApiController controller = new AiApiController(processor, streaming);
    private final PolicyGenerationItem item = new PolicyGenerationItem("let auditors read the reports", null);

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void aGeneratedPolicyCarriesTheServerTimeAndNoPipelineDetails() {
        PolicyResponse response = new PolicyResponse();
        BusinessPolicyDto policy = new BusinessPolicyDto();
        policy.setPolicyName("Auditors read reports");
        response.setPolicyData(policy);
        response.setReasoning("Auditors need read access.");
        response.withMetadata("promptTemplateClass", "PolicyGenerationTemplate");
        when(streaming.process(any(), eq(processor), eq(PolicyResponse.class))).thenReturn(Mono.just(response));
        LocalDateTime before = LocalDateTime.now();

        ResponseEntity<Object> answer = controller.generatePolicyFromText(item).block();

        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.OK);
        GeneratedPolicy body = (GeneratedPolicy) answer.getBody();
        assertThat(body.policyData().getPolicyName()).isEqualTo("Auditors read reports");
        assertThat(body.reasoning()).isEqualTo("Auditors need read access.");
        assertThat(body.timestamp()).isAfterOrEqualTo(before);
        assertThat(GeneratedPolicy.class.getRecordComponents())
                .extracting(component -> component.getName())
                .doesNotContain("metadata", "allMetadata");
        ArgumentCaptor<AIRequest> request = ArgumentCaptor.forClass(AIRequest.class);
        verify(streaming).process(request.capture(), eq(processor), eq(PolicyResponse.class));
        assertThat(request.getValue().getParameters()).containsEntry("pipelineFailurePolicy", "PROPAGATE_ERROR");
    }

    @Test
    void anUnreachableModelIsAServiceUnavailableWithItsReason() {
        when(streaming.process(any(), eq(processor), eq(PolicyResponse.class))).thenReturn(Mono.error(
                new IllegalStateException("Pipeline failed", new ResourceAccessException("I/O error",
                        new ConnectException("Connection refused")))));

        ResponseEntity<Object> answer = controller.generatePolicyFromText(item).block();

        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(code(answer)).isEqualTo(AiApiController.MODEL_UNREACHABLE);
    }

    @Test
    void anAnswerWithoutAPolicyIsNotASuccess() {
        PolicyResponse empty = new PolicyResponse();
        empty.setReasoning("No available items found.");
        when(streaming.process(any(), eq(processor), eq(PolicyResponse.class))).thenReturn(Mono.just(empty));

        ResponseEntity<Object> answer = controller.generatePolicyFromText(item).block();

        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        assertThat(code(answer)).isEqualTo(AiApiController.NO_POLICY);
    }

    @Test
    void aSyntheticErrorResponseIsAFailure() {
        PolicyResponse failed = new PolicyResponse();
        failed.withError("Pipeline execution failed: VectorStoreException");
        when(streaming.process(any(), eq(processor), eq(PolicyResponse.class))).thenReturn(Mono.just(failed));

        ResponseEntity<Object> answer = controller.generatePolicyFromText(item).block();

        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(code(answer)).isEqualTo(AiApiController.GENERATION_FAILED);
    }

    /**
     * IAM-D62: the stream the policy center reads ends a failure with its error event, whose message is said in the
     * language of the screen by its code.
     */
    @Test
    @SuppressWarnings("unchecked")
    void aStreamFailureIsAnErrorEventInTheScreensLanguage() throws Exception {
        StaticMessageSource messages = new StaticMessageSource();
        messages.addMessage("aiPolicy.generation.error.AI_MODEL_UNREACHABLE", Locale.KOREAN, "AI 모델 서버에 연결할 수 없습니다.");
        AiApiController localized = new AiApiController(processor, streaming, messages);
        when(streaming.stream(any(), eq(processor))).thenReturn(Flux.just(ServerSentEvent.<String>builder()
                .event("error").data("{\"code\":\"AI_MODEL_UNREACHABLE\",\"message\":\"The AI model server cannot be reached.\"}")
                .build()));
        LocaleContextHolder.setLocale(Locale.KOREAN);
        try {
            List<ServerSentEvent<String>> events = localized.generatePolicyFromTextStream(item).collectList().block();

            assertThat(events).singleElement().extracting(ServerSentEvent::event).isEqualTo("error");
            Map<String, Object> failure = new ObjectMapper().readValue(events.get(0).data(), Map.class);
            assertThat(failure).containsEntry("code", "AI_MODEL_UNREACHABLE")
                    .containsEntry("message", "AI 모델 서버에 연결할 수 없습니다.");
        } finally {
            LocaleContextHolder.resetLocaleContext();
        }
    }

    private static Object code(ResponseEntity<Object> answer) {
        Map<String, Object> properties = ((ProblemDetail) answer.getBody()).getProperties();
        return properties == null ? null : properties.get("code");
    }
}
