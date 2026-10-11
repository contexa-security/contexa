package io.contexa.contexaiam.admin.promptquality.governance;

import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class PromptReleaseApiControllerTest {

    @Test
    void releasesAreServedUnderThePromptQualityNamespaceWithTheScopeFilter() throws Exception {
        JdbcPromptReleaseQueryService service = mock(JdbcPromptReleaseQueryService.class);
        when(service.releases("PLATFORM_GLOBAL")).thenReturn(new JdbcPromptReleaseQueryService.PromptReleaseSnapshot(List.of(
                new JdbcPromptReleaseQueryService.PromptReleaseRow(
                        "PLATFORM_GLOBAL", "cortex.security-decision", "SecurityDecisionStandard", "2026.07.30-v19",
                        "CORTEX_PROMPT_CONTRACT_V2", "PRODUCTION", "ACTIVE", "hash", "APPROVED", "PRODUCTION",
                        "2026.07.26-v5", "2026.07.26-v5", "TARGET_DECLARED", "READY", "PQA-ROLLBACK:1", "READY",
                        "READY", null, LocalDateTime.of(2026, 10, 10, 9, 0)))));
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new PromptReleaseApiController(service)).build();

        mockMvc.perform(get("/contexa/admin/api/prompt-quality/releases").param("registryScope", "PLATFORM_GLOBAL"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.releases[0].promptKey").value("cortex.security-decision"))
                .andExpect(jsonPath("$.releases[0].templateKey").value("SecurityDecisionStandard"))
                .andExpect(jsonPath("$.releases[0].bundleState").value("ACTIVE"))
                .andExpect(jsonPath("$.releases[0].approvalState").value("APPROVED"))
                .andExpect(jsonPath("$.releases[0].rollbackReadinessState").value("READY"));
        verify(service).releases("PLATFORM_GLOBAL");
    }
}
