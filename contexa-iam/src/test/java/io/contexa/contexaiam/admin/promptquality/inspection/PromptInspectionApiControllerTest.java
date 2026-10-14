package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexacore.verification.inspection.PromptInspectionReinspection;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The inspection console API: the overview and the package list of a period (the last seven days by default), a
 * package's detail, and the operator's re-inspection of a package or a period with its progress.
 */
class PromptInspectionApiControllerTest {

    private static final Instant NOW = Instant.parse("2026-10-12T06:00:00Z");
    private static final String ROOT = "/contexa/admin/api/prompt-inspection";

    private final JdbcPromptInspectionQueries queries = mock(JdbcPromptInspectionQueries.class);
    private final PromptInspectionConsole console = mock(PromptInspectionConsole.class);
    private final PromptInspectionReinspection reinspection = mock(PromptInspectionReinspection.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new PromptInspectionApiController(queries, console,
            reinspection, Clock.fixed(NOW, ZoneOffset.UTC))).build();

    @Test
    void theOverviewIsOfTheLastSevenDaysUnlessAPeriodIsGiven() throws Exception {
        Instant weekAgo = NOW.minusSeconds(7 * 24 * 3600L);
        when(queries.overview(weekAgo, NOW)).thenReturn(new JdbcPromptInspectionQueries.Overview(weekAgo, NOW,
                Map.of("FAIL", 2L), List.of(), List.of(), List.of(), List.of(), List.of()));

        mvc.perform(get(ROOT + "/overview")).andExpect(status().isOk())
                .andExpect(jsonPath("$.verdicts.FAIL").value(2));

        mvc.perform(get(ROOT + "/overview").param("from", "2026-10-01T00:00:00Z").param("to", "2026-10-02T00:00:00Z"))
                .andExpect(status().isOk());
        verify(queries).overview(Instant.parse("2026-10-01T00:00:00Z"), Instant.parse("2026-10-02T00:00:00Z"));
    }

    @Test
    void aPackageListWithoutAPageSizeTakesTheScreensPageSize() throws Exception {
        when(queries.packages(any(), anyInt(), anyInt())).thenReturn(
                new JdbcPromptInspectionQueries.PackagePage(0, 0, 20, List.of()));

        mvc.perform(get(ROOT + "/packages")).andExpect(status().isOk());

        verify(queries).packages(any(), eq(0), eq(Integer.parseInt(PromptInspectionScreen.DEFAULT_PAGE_SIZE)));
    }

    @Test
    void thePackageListPassesItsFilterAndPage() throws Exception {
        when(queries.packages(any(), anyInt(), anyInt())).thenReturn(
                new JdbcPromptInspectionQueries.PackagePage(1, 2, 10, List.of()));

        mvc.perform(get(ROOT + "/packages").param("verdict", "FAIL").param("checkCode", "FACT_ACCURACY")
                        .param("block", "REQUEST").param("entry", "Action").param("page", "2").param("size", "10"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.total").value(1));

        ArgumentCaptor<JdbcPromptInspectionQueries.PackageFilter> filter =
                ArgumentCaptor.forClass(JdbcPromptInspectionQueries.PackageFilter.class);
        verify(queries).packages(filter.capture(), eq(2), eq(10));
        assertThat(filter.getValue()).isEqualTo(new JdbcPromptInspectionQueries.PackageFilter(
                NOW.minusSeconds(7 * 24 * 3600L), NOW, "FAIL", "FACT_ACCURACY", "REQUEST", "Action"));
    }

    @Test
    void aPackageDetailIsFoundOrNot() throws Exception {
        when(console.detail("p1")).thenReturn(Optional.of(new PromptInspectionConsole.Detail("p1", NOW, "user-1",
                "POST", "/x", "r", "PASS", "prompt-inspector/1", "d", "v20-dictionary-blocks", null, List.of(),
                List.of(), List.of(), null, null, List.of())));
        when(console.detail("none")).thenReturn(Optional.empty());

        mvc.perform(get(ROOT + "/packages/p1")).andExpect(status().isOk())
                .andExpect(jsonPath("$.packageId").value("p1"));
        mvc.perform(get(ROOT + "/packages/none")).andExpect(status().isNotFound());
    }

    @Test
    void aPackageIsReinspectedAtOnce() throws Exception {
        when(reinspection.reinspect("p1")).thenReturn(Optional.of(new PromptInspectionResult("p1",
                "prompt-inspector/1", "d", "v20-dictionary-blocks", PromptInspectionVerdict.INCOMPLETE, List.of(),
                null)));
        when(reinspection.reinspect("none")).thenReturn(Optional.empty());

        mvc.perform(post(ROOT + "/packages/p1/reinspect")).andExpect(status().isOk())
                .andExpect(jsonPath("$.verdict").value("INCOMPLETE"));
        mvc.perform(post(ROOT + "/packages/none/reinspect")).andExpect(status().isNotFound());
    }

    /** R1b-6: a period is left to the automatic round to inspect again; its progress is one count of the period. */
    @Test
    void aPeriodIsInspectedAgainByTheRoundAndItsProgressIsOneCount() throws Exception {
        Instant from = Instant.parse("2026-10-11T00:00:00Z");
        Instant to = Instant.parse("2026-10-12T00:00:00Z");
        when(reinspection.request(from, to)).thenReturn(new PromptInspectionReinspection.PeriodStatus(from, to, 4, 4));
        when(reinspection.status(from, to)).thenReturn(new PromptInspectionReinspection.PeriodStatus(from, to, 4, 1));

        mvc.perform(post(ROOT + "/reinspections").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"from\":\"2026-10-11T00:00:00Z\",\"to\":\"2026-10-12T00:00:00Z\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.packages").value(4))
                .andExpect(jsonPath("$.uninspected").value(4));
        mvc.perform(get(ROOT + "/reinspections").param("from", "2026-10-11T00:00:00Z").param("to", "2026-10-12T00:00:00Z"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.uninspected").value(1));
        mvc.perform(post(ROOT + "/reinspections").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
        mvc.perform(get(ROOT + "/reinspections").param("from", "2026-10-12T00:00:00Z").param("to", "2026-10-11T00:00:00Z"))
                .andExpect(status().isBadRequest());
    }
}
