package io.contexa.showcase.workload.contexa.internal;

import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.http.ResponseEntity;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * W8-3: the harness's rollback on control D goes through the OSS rollback service as the harness, its approval as a
 * second harness actor, and the service's refusal comes back as 422 with the refusals.
 */
class PromptRollbackHarnessControllerTest {

    private static final PromptBundleRollbackService.Request REQUEST = new PromptBundleRollbackService.Request(
            "PLATFORM_GLOBAL", "cortex.security-decision", "2026.10.16-v20.23", "2026.10.16-v19.19",
            "P8 rollback rehearsal", true);

    private final PromptBundleRollbackService service = mock(PromptBundleRollbackService.class);

    @Test
    void theHarnessAsksTheRollbackAndASecondActorApprovesIt() {
        when(service.rollback(REQUEST, PromptRollbackHarnessController.ACTOR)).thenReturn(
                new PromptBundleRollbackService.Result("rb-1", PromptBundleRollbackService.AWAITING_APPROVAL, null,
                        List.of()));
        when(service.approve("rb-1", PromptRollbackHarnessController.APPROVER)).thenReturn(
                new PromptBundleRollbackService.Result("rb-1", PromptBundleRollbackService.APPROVED, null, List.of()));

        ResponseEntity<PromptBundleRollbackService.Result> asked = controller(true).rollback(REQUEST);
        ResponseEntity<PromptBundleRollbackService.Result> approved = controller(true).approve("rb-1");

        assertThat(asked.getStatusCode().value()).isEqualTo(200);
        assertThat(asked.getBody().status()).isEqualTo(PromptBundleRollbackService.AWAITING_APPROVAL);
        assertThat(approved.getBody().status()).isEqualTo(PromptBundleRollbackService.APPROVED);
        assertThat(PromptRollbackHarnessController.APPROVER).isNotEqualTo(PromptRollbackHarnessController.ACTOR);
    }

    @Test
    void aRefusedRollbackIsUnprocessableWithItsRefusals() {
        when(service.rollback(REQUEST, PromptRollbackHarnessController.ACTOR)).thenReturn(
                new PromptBundleRollbackService.Result("rb-2", PromptBundleRollbackService.REFUSED, null,
                        List.of("TARGET_NOT_IN_BUILD")));

        ResponseEntity<PromptBundleRollbackService.Result> response = controller(true).rollback(REQUEST);

        assertThat(response.getStatusCode().value()).isEqualTo(422);
        assertThat(response.getBody().refusals()).containsExactly("TARGET_NOT_IN_BUILD");
    }

    @Test
    void withoutTheRollbackServiceTheRoutesAreNotFound() {
        assertThat(controller(false).rollback(REQUEST).getStatusCode().value()).isEqualTo(404);
        assertThat(controller(false).approve("rb-1").getStatusCode().value()).isEqualTo(404);
    }

    private PromptRollbackHarnessController controller(boolean withService) {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        if (withService) {
            beans.addBean("rollbacks", service);
        }
        return new PromptRollbackHarnessController(beans.getBeanProvider(PromptBundleRollbackService.class));
    }
}
