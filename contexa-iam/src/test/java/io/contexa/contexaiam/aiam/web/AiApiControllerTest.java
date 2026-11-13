package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.streaming.StandardStreamingService;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.ResourceAccessException;
import reactor.core.publisher.Mono;

import java.net.ConnectException;
import java.time.LocalDateTime;
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
        AiApiController.GeneratedPolicy body = (AiApiController.GeneratedPolicy) answer.getBody();
        assertThat(body.policyData().getPolicyName()).isEqualTo("Auditors read reports");
        assertThat(body.reasoning()).isEqualTo("Auditors need read access.");
        assertThat(body.timestamp()).isAfterOrEqualTo(before);
        assertThat(AiApiController.GeneratedPolicy.class.getRecordComponents())
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

    private static Object code(ResponseEntity<Object> answer) {
        Map<String, Object> properties = ((ProblemDetail) answer.getBody()).getProperties();
        return properties == null ? null : properties.get("code");
    }
}
