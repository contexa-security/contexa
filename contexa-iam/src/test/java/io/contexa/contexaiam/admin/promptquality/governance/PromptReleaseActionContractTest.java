package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

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
 * W7-14: what the version screen's buttons rely on. A transition button sends its canonical state, which the API
 * reads through the one table of every vocabulary and asks the gate for (N-GOV-4), and a gate refusal comes back as
 * 422 with the receipt's blockers; a refused rollback or approval comes back as 422 with its refusals. The calls run
 * as the signed-in administrator.
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

    /**
     * N-GOV-4: the screen sent the release status of the descriptor vocabulary (its settings' releaseStatuses table),
     * because the API read only that vocabulary; the API reads the canonical names, so the screen sends its state as it
     * names it and the table is gone.
     */
    @Test
    void theScreenAsksForTheCanonicalState() throws IOException {
        assertThat(PromptReleaseScreen.scriptSettings()).doesNotContainKey("releaseStatuses");
        assertThat(script("static/contexa/js/admin/prompt-release/detail-page.js"))
                .contains("targetReleaseStatus: targetState,").doesNotContain("releaseStatuses");
    }

    @Test
    void aCanonicalStateIsTheStateTheGateIsAskedFor() throws Exception {
        for (PromptBundleState state : List.of(PromptBundleState.SHADOW, PromptBundleState.ACTIVE,
                PromptBundleState.DEPRECATED)) {
            when(gate.transitionPromptRelease(eq("PLATFORM_GLOBAL"), eq(KEY), eq(VERSION), eq(state),
                    eq("operator-a"), any(), eq("OSS_OPERATOR_API"))).thenReturn(
                    new PromptGovernanceReleaseGateService.ReleaseTransitionReceipt("PLATFORM_GLOBAL", KEY, VERSION,
                            "CANARY", state.name(), true, "READY", List.of(), null));

            mvc.perform(post(ROOT + "/transition").principal(operator).contentType(MediaType.APPLICATION_JSON)
                            .content(transitionBody(state.name())))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.targetReleaseStatus").value(state.name()));
        }
    }

    @Test
    void aNameOfNoVocabularyIsABadRequestAndTheGateIsNotAsked() throws Exception {
        mvc.perform(post(ROOT + "/transition").principal(operator).contentType(MediaType.APPLICATION_JSON)
                        .content(transitionBody("LIVE")))
                .andExpect(status().isBadRequest());
        verify(gate, never()).transitionPromptRelease(anyString(), anyString(), anyString(),
                any(PromptBundleState.class), anyString(), any(), anyString());
    }

    @Test
    void aGateRefusalIsA422WithTheReceiptsBlockers() throws Exception {
        // N-GOV-4: the API asks the gate for the canonical state the requested name reads as.
        when(gate.transitionPromptRelease(eq("PLATFORM_GLOBAL"), eq(KEY), eq(VERSION), eq(PromptBundleState.CANARY),
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
        // N-GOV-4: an older name (EVAL_ONLY here) reads through the one table as its canonical state.
        when(gate.transitionPromptRelease(eq("PLATFORM_GLOBAL"), eq(KEY), eq(VERSION), eq(PromptBundleState.SHADOW),
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

    private static String transitionBody(String target) {
        return "{\"registryScope\":\"PLATFORM_GLOBAL\",\"promptKey\":\"" + KEY + "\",\"promptVersion\":\"" + VERSION
                + "\",\"targetReleaseStatus\":\"" + target + "\",\"rationale\":\"N-GOV-4 test\"}";
    }

    private static String script(String resource) throws IOException {
        try (InputStream input = PromptReleaseActionContractTest.class.getClassLoader().getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
