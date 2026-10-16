package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * W7-14: the read API of the version screens under the prompt quality release path: the bundle list with the gate's
 * answer, a bundle's gate (404 when the registry does not hold it) and the comparison, over the last seven days unless
 * a period is given.
 */
class PromptReleaseConsoleApiControllerTest {

    private static final String ROOT = "/contexa/admin/api/prompt-quality/releases";
    private static final Instant NOW = Instant.parse("2026-10-16T09:00:00Z");

    private final PromptReleaseConsole console = mock(PromptReleaseConsole.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new PromptReleaseConsoleApiController(console,
            Clock.fixed(NOW, ZoneOffset.UTC))).build();

    @Test
    void theBundleListCarriesTheCanonicalStateAndTheGatesAnswer() throws Exception {
        when(console.bundles("PLATFORM_GLOBAL")).thenReturn(List.of(new PromptReleaseConsole.BundleRow("PLATFORM_GLOBAL",
                "cortex.security-decision", "2026.10.16-v20.23", "a".repeat(64), "SHADOW", null,
                new PromptReleaseConsole.Canary(null, null, null), true, true,
                List.of(new PromptGovernanceReleaseGateService.ReleaseGateTarget("CANARY", true, "READY_FOR_CANARY",
                        List.of())), true, LocalDateTime.of(2026, 10, 16, 8, 0))));

        mvc.perform(get(ROOT + "/bundles").param("registryScope", "PLATFORM_GLOBAL"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].bundleVersion").value("2026.10.16-v20.23"))
                .andExpect(jsonPath("$[0].state").value("SHADOW"))
                .andExpect(jsonPath("$[0].gate[0].targetState").value("CANARY"))
                .andExpect(jsonPath("$[0].gate[0].ready").value(true))
                .andExpect(jsonPath("$[0].gateRead").value(true));
    }

    @Test
    void aBundleTheRegistryDoesNotHoldIsNotFound() throws Exception {
        when(console.detail("PLATFORM_GLOBAL", "cortex.security-decision", "2026.01.01-v0"))
                .thenReturn(Optional.empty());

        mvc.perform(get(ROOT + "/gate").param("registryScope", "PLATFORM_GLOBAL")
                        .param("promptKey", "cortex.security-decision").param("promptVersion", "2026.01.01-v0"))
                .andExpect(status().isNotFound());
    }

    @Test
    void theComparisonReadsTheLastSevenDaysUnlessAPeriodIsGiven() throws Exception {
        mvc.perform(get(ROOT + "/compare").param("promptKey", "cortex.security-decision")
                        .param("base", "2026.10.16-v19.19").param("candidate", "2026.10.16-v20.23"))
                .andExpect(status().isOk());

        verify(console).compare(null, "cortex.security-decision", "2026.10.16-v19.19", "2026.10.16-v20.23",
                NOW.minus(Duration.ofDays(7)), NOW);
    }

    /** N-SHD-1: the comparison carries each shadow run paired with the decision of its request. */
    @Test
    void theComparisonPairsEachShadowRunWithTheDecisionOfItsRequest() throws Exception {
        JdbcPromptInspectionQueries.ShadowPair pair = new JdbcPromptInspectionQueries.ShadowPair("req-1",
                Instant.parse("2026-10-16T08:00:00Z"), "s-1", "2026.10.16-v20.23", "ALLOW", "d-1",
                "2026.10.16-v19.19", "BLOCK");
        when(console.compare(any(), any(), any(), any(), any(), any())).thenReturn(new PromptReleaseConsole.Comparison(
                "PLATFORM_GLOBAL", "cortex.security-decision", null, null, List.of(), NOW.minus(Duration.ofDays(7)),
                NOW, List.of(), PromptReleaseConsole.cases(List.of(pair)), List.of()));

        mvc.perform(get(ROOT + "/compare").param("promptKey", "cortex.security-decision")
                        .param("base", "2026.10.16-v19.19").param("candidate", "2026.10.16-v20.23"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cases.shadows").value(1))
                .andExpect(jsonPath("$.cases.paired").value(1))
                .andExpect(jsonPath("$.cases.changed").value(1))
                .andExpect(jsonPath("$.cases.changes[0].decisionAction").value("BLOCK"))
                .andExpect(jsonPath("$.cases.changes[0].shadowAction").value("ALLOW"))
                .andExpect(jsonPath("$.cases.pairs[0].requestId").value("req-1"))
                .andExpect(jsonPath("$.cases.pairs[0].decisionPackageId").value("d-1"))
                .andExpect(jsonPath("$.cases.pairs[0].shadowPackageId").value("s-1"));
    }

    @Test
    void aPeriodThatEndsBeforeItStartsIsRefused() throws Exception {
        mvc.perform(get(ROOT + "/compare").param("promptKey", "cortex.security-decision")
                        .param("base", "2026.10.16-v19.19").param("candidate", "2026.10.16-v20.23")
                        .param("from", "2026-10-16T00:00:00Z").param("to", "2026-10-15T00:00:00Z"))
                .andExpect(status().isBadRequest());

        verify(console, never()).compare(any(), any(), any(), any(), any(), any());
    }
}
