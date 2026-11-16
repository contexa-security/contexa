/*
 * Copyright 2026 The Contexa Project
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.admin.web.monitoring.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Console plan 5-2: the AI monitor's addresses after its code was replaced by the Zero Trust console. */
class AiMonitorControllerTest {

    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new AiMonitorController()).build();

    /** An old address or bookmark opens the console screen that answers the same question. */
    @Test
    void theOldPagesOpenTheConsoleScreens() throws Exception {
        mvc.perform(get("/contexa/admin/ai-monitor").principal(admin()))
                .andExpect(redirectedUrl("/contexa/admin/zero-trust"));
        mvc.perform(get("/contexa/admin/ai-monitor/overview").principal(admin()).param("period", "month"))
                .andExpect(redirectedUrl("/contexa/admin/zero-trust?period=month"));
        mvc.perform(get("/contexa/admin/ai-monitor/llm").principal(admin()).param("period", "DAY"))
                .andExpect(redirectedUrl("/contexa/admin/zero-trust/trust?period=day"));
        mvc.perform(get("/contexa/admin/ai-monitor/failures").principal(admin()).param("period", "all"))
                .andExpect(redirectedUrl("/contexa/admin/zero-trust/operations"));
        mvc.perform(get("/contexa/admin/ai-monitor/operations").principal(admin()))
                .andExpect(redirectedUrl("/contexa/admin/zero-trust/operations"));
        mvc.perform(get("/contexa/admin/ai-monitor/readiness").principal(admin()).param("period", "week"))
                .andExpect(redirectedUrl("/contexa/admin/zero-trust/adoption"));
    }

    /**
     * The AI monitor's JSON and CSV are gone with it (the console serves its numbers and CSVs), and so is the reset that
     * deleted every decision row (console design 11.4: the retention cleans them).
     */
    @Test
    void theAiMonitorsApisHaveNoMapping() throws Exception {
        for (String api : new String[] {"overview", "llm", "failures", "readiness", "session/current",
                "session/summaries", "export.csv", "correlation", "hcad"}) {
            mvc.perform(get("/contexa/admin/api/ai-monitor/" + api).principal(admin())).andExpect(status().isNotFound());
        }
        mvc.perform(post("/contexa/admin/api/ai-monitor/reset").principal(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"confirmationText\":\"RESET\",\"reason\":\"new window\"}"))
                .andExpect(status().isNotFound());
        mvc.perform(get("/contexa/admin/api/security-monitor/hcad/summary").principal(admin()))
                .andExpect(status().isNotFound());
    }

    @Test
    void theOldPagesRejectNonAdminUsers() throws Exception {
        mvc.perform(get("/contexa/admin/ai-monitor").principal(new TestingAuthenticationToken("user", "n/a", "ROLE_USER")))
                .andExpect(status().isForbidden());
    }

    private TestingAuthenticationToken admin() {
        return new TestingAuthenticationToken("admin", "n/a", "ROLE_ADMIN");
    }
}
