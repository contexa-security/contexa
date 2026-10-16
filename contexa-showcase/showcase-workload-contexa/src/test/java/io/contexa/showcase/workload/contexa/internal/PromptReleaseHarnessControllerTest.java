package io.contexa.showcase.workload.contexa.internal;

import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceRegistryService;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptGovernanceRuntimeCacheInvalidationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.http.ResponseEntity;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * W6-9 (P6): the harness's release transition on control D goes through the OSS release gate with the harness as the
 * actor, tells the runtime caches when the gate applied it, and returns the gate's receipt either way.
 */
class PromptReleaseHarnessControllerTest {

    private static final String SCOPE = PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE;
    private static final String VERSION = "2026.10.16-v20.23";

    private final PromptGovernanceReleaseGateService gate = mock(PromptGovernanceReleaseGateService.class);
    private final PromptGovernanceRuntimeCacheInvalidationService caches =
            mock(PromptGovernanceRuntimeCacheInvalidationService.class);

    @Test
    void anAppliedShadowReleaseIsReturnedAndTheCachesAreTold() {
        when(gate.transitionPromptRelease(SCOPE, PromptReleaseHarnessController.PROMPT_KEY, VERSION,
                PromptReleaseStatus.EVAL_ONLY, PromptReleaseHarnessController.ACTOR, "shadow check",
                PromptReleaseHarnessController.SOURCE)).thenReturn(receipt(true, List.of()));

        ResponseEntity<PromptGovernanceReleaseGateService.ReleaseTransitionReceipt> response = controller(true)
                .transition(new PromptReleaseHarnessController.TransitionRequest(VERSION, PromptReleaseStatus.EVAL_ONLY,
                        "shadow check"));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().applied()).isTrue();
        verify(caches).publish(SCOPE, PromptReleaseHarnessController.PROMPT_KEY, VERSION,
                "release transition to EVAL_ONLY", PromptReleaseHarnessController.ACTOR);
    }

    @Test
    void aRefusedTransitionReturnsTheGatesReceiptAndTellsNoCache() {
        when(gate.transitionPromptRelease(anyString(), anyString(), anyString(), any(),
                anyString(), anyString(), anyString())).thenReturn(receipt(false, List.of("ILLEGAL_STATE_TRANSITION")));

        ResponseEntity<PromptGovernanceReleaseGateService.ReleaseTransitionReceipt> response = controller(true)
                .transition(new PromptReleaseHarnessController.TransitionRequest(VERSION, PromptReleaseStatus.CANARY,
                        "canary"));

        assertThat(response.getStatusCode().value()).isEqualTo(422);
        assertThat(response.getBody().blockers()).containsExactly("ILLEGAL_STATE_TRANSITION");
        verify(caches, never()).publish(anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void withoutTheGateTheRouteIsNotFoundAndARequestWithoutAReasonIsRefused() {
        assertThat(controller(false).transition(new PromptReleaseHarnessController.TransitionRequest(VERSION,
                PromptReleaseStatus.EVAL_ONLY, "shadow check")).getStatusCode().value()).isEqualTo(404);
        assertThat(controller(true).transition(new PromptReleaseHarnessController.TransitionRequest(VERSION,
                PromptReleaseStatus.EVAL_ONLY, " ")).getStatusCode().value()).isEqualTo(400);
    }

    private PromptReleaseHarnessController controller(boolean withGate) {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        if (withGate) {
            beans.addBean("gate", gate);
        }
        beans.addBean("caches", caches);
        return new PromptReleaseHarnessController(beans.getBeanProvider(PromptGovernanceReleaseGateService.class),
                beans.getBeanProvider(PromptGovernanceRuntimeCacheInvalidationService.class));
    }

    private static PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt(boolean applied,
                                                                                      List<String> blockers) {
        return new PromptGovernanceReleaseGateService.ReleaseTransitionReceipt(SCOPE,
                PromptReleaseHarnessController.PROMPT_KEY, VERSION, "AVAILABLE", "SHADOW", applied,
                applied ? "READY" : "BLOCKED", blockers, LocalDateTime.of(2026, 10, 16, 3, 0));
    }
}
