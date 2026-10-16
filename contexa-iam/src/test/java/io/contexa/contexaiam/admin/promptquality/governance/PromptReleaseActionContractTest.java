package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * W7-14: what the version screen's buttons rely on. A transition button sends the release status of its canonical
 * state (the screen settings' table) and a gate refusal comes back as 422 with the receipt's blockers; a refused
 * rollback or approval comes back as 422 with its refusals. The calls run as the signed-in administrator.
 */
class PromptReleaseActionContractTest {

    private static final String ROOT = "/contexa/admin/api/prompt-quality/releases";
    private static final String KEY = "cortex.security-decision";
    private static final String VERSION = "2026.10.16-v20.23";

    private final PromptGovernanceReleaseGateService gate = mock(PromptGovernanceReleaseGateService.class);
    private final PromptGovernanceRuntimeCacheInvalidationService invalidation =
            mock(PromptGovernanceRuntimeCacheInvalidationService.class);
    private final PromptBundleRollbackService rollbacks = mock(PromptBundleRollbackService.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(
            new PromptReleaseTransitionApiController(gate, invalidation),
            new PromptBundleRollbackApiController(rollbacks)).build();
    private final TestingAuthenticationToken operator = new TestingAuthenticationToken("operator-a", null);

    @Test
    void theScreenAsksForTheReleaseStatusOfTheCanonicalState() {
        @SuppressWarnings("unchecked")
        Map<String, String> statuses = (Map<String, String>) PromptReleaseScreen.scriptSettings()
                .get("releaseStatuses");

        assertThat(statuses).containsEntry("SHADOW", "EVAL_ONLY")
                .containsEntry("CANARY", "CANARY").containsEntry("ACTIVE", "PRODUCTION")
                .containsEntry("DEPRECATED", "ROLLED_BACK").containsEntry("AVAILABLE", "DRAFT");
    }

    @Test
    void aGateRefusalIsA422WithTheReceiptsBlockers() throws Exception {
        when(gate.transitionPromptRelease(eq("PLATFORM_GLOBAL"), eq(KEY), eq(VERSION), eq(PromptReleaseStatus.CANARY),
                eq("operator-a"), any(), eq("OSS_OPERATOR_API"))).thenReturn(
                new PromptGovernanceReleaseGateService.ReleaseTransitionReceipt("PLATFORM_GLOBAL", KEY, VERSION,
                        "SHADOW", "CANARY", false, "BLOCKED_BY_BUDGET_GOVERNANCE_GAP",
                        List.of("BUDGET_PROFILE_MISSING governed budget profiles must exist before canary rollout."),
                        null));

        mvc.perform(post(ROOT + "/transition").principal(operator).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registryScope\":\"PLATFORM_GLOBAL\",\"promptKey\":\"" + KEY + "\","
                                + "\"promptVersion\":\"" + VERSION + "\",\"targetReleaseStatus\":\"CANARY\","
                                + "\"rationale\":\"canary for the tenant\"}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.applied").value(false))
                .andExpect(jsonPath("$.blockers[0]").value(
                        "BUDGET_PROFILE_MISSING governed budget profiles must exist before canary rollout."));
        verify(invalidation, never()).publish(anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void anAppliedTransitionTellsTheRuntimeCaches() throws Exception {
        when(gate.transitionPromptRelease(eq("PLATFORM_GLOBAL"), eq(KEY), eq(VERSION), eq(PromptReleaseStatus.EVAL_ONLY),
                eq("operator-a"), any(), eq("OSS_OPERATOR_API"))).thenReturn(
                new PromptGovernanceReleaseGateService.ReleaseTransitionReceipt("PLATFORM_GLOBAL", KEY, VERSION,
                        "AVAILABLE", "SHADOW", true, "READY_FOR_EVAL_ONLY", List.of(), null));

        mvc.perform(post(ROOT + "/transition").principal(operator).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registryScope\":\"PLATFORM_GLOBAL\",\"promptKey\":\"" + KEY + "\","
                                + "\"promptVersion\":\"" + VERSION + "\",\"targetReleaseStatus\":\"EVAL_ONLY\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.targetReleaseStatus").value("SHADOW"));
        verify(invalidation).publish(eq("PLATFORM_GLOBAL"), eq(KEY), eq(VERSION), anyString(), eq("operator-a"));
    }

    @Test
    void aRefusedRollbackIsA422WithItsRefusals() throws Exception {
        when(rollbacks.rollback(any(PromptBundleRollbackService.Request.class), eq("operator-a"))).thenReturn(
                new PromptBundleRollbackService.Result("RBX-1", PromptBundleRollbackService.REFUSED, null,
                        List.of("TARGET_NOT_DECLARED")));
        when(rollbacks.approve("RBX-2", "operator-a")).thenReturn(new PromptBundleRollbackService.Result("RBX-2",
                PromptBundleRollbackService.REFUSED, null, List.of("APPROVER_IS_ACTOR")));

        mvc.perform(post(ROOT + "/rollback").principal(operator).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registryScope\":\"PLATFORM_GLOBAL\",\"promptKey\":\"" + KEY + "\","
                                + "\"fromVersion\":\"" + VERSION + "\",\"toVersion\":\"2026.10.15-v19.17\","
                                + "\"reason\":\"bad answers\",\"emergency\":false}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.refusals[0]").value("TARGET_NOT_DECLARED"));
        mvc.perform(post(ROOT + "/rollback/RBX-2/approve").principal(operator))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.refusals[0]").value("APPROVER_IS_ACTOR"));
    }
}
