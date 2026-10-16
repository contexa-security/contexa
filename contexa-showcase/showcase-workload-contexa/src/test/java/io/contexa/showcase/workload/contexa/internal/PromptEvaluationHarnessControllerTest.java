package io.contexa.showcase.workload.contexa.internal;

import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceEmpiricalEvalService;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceRegistryService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.http.ResponseEntity;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * W8-3: the harness's evaluation on control D goes to the OSS empirical evaluation service with the bundle hash and
 * the runs it counted, as the harness; one without a bundle hash or runs is refused before it is recorded.
 */
class PromptEvaluationHarnessControllerTest {

    private static final String VERSION = "2026.10.16-v20.23";

    private final PromptGovernanceEmpiricalEvalService service = mock(PromptGovernanceEmpiricalEvalService.class);

    @Test
    void anEvaluationIsRecordedWithItsBundleHashAndRuns() {
        when(service.recordEvaluation(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                PromptReleaseHarnessController.PROMPT_KEY, VERSION, "p8-measurement", "SHOWCASE_HARNESS",
                List.of("PROMPT_INJECTION"), "PASSED", "NOT_VERIFIED", "NOT_VERIFIED",
                PromptReleaseHarnessController.ACTOR, "P8", "bundle-hash", "protocol-1"))
                .thenReturn(new PromptGovernanceEmpiricalEvalService.EvalRegistrationReceipt(
                        PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, PromptReleaseHarnessController.PROMPT_KEY,
                        VERSION, "NEEDS_REVIEW", "NOT_VERIFIED", LocalDateTime.of(2026, 10, 16, 3, 0)));

        ResponseEntity<PromptGovernanceEmpiricalEvalService.EvalRegistrationReceipt> response = controller(true)
                .record(request("bundle-hash", "protocol-1"));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().promptVersion()).isEqualTo(VERSION);
    }

    @Test
    void anEvaluationWithoutItsBundleHashOrRunsIsRefused() {
        assertThat(controller(true).record(request(" ", "protocol-1")).getStatusCode().value()).isEqualTo(400);
        assertThat(controller(true).record(request("bundle-hash", null)).getStatusCode().value()).isEqualTo(400);
        verify(service, never()).recordEvaluation(anyString(), anyString(), anyString(), anyString(), anyString(),
                anyList(), anyString(), anyString(), anyString(), anyString(), anyString(), any(), any());
    }

    @Test
    void withoutTheServiceTheRouteIsNotFound() {
        assertThat(controller(false).record(request("bundle-hash", "protocol-1")).getStatusCode().value())
                .isEqualTo(404);
    }

    private static PromptEvaluationHarnessController.EvaluationRequest request(String hash, String runs) {
        return new PromptEvaluationHarnessController.EvaluationRequest(VERSION, "p8-measurement", "SHOWCASE_HARNESS",
                List.of("PROMPT_INJECTION"), "PASSED", "NOT_VERIFIED", "NOT_VERIFIED", "P8", hash, runs);
    }

    private PromptEvaluationHarnessController controller(boolean withService) {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        if (withService) {
            beans.addBean("evaluations", service);
        }
        return new PromptEvaluationHarnessController(beans.getBeanProvider(PromptGovernanceEmpiricalEvalService.class));
    }
}
