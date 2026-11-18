/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.admin.promptquality.version;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentException;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionProblem;
import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Counts;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Created;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ListView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.PromptChoice;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Receipt;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Running;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Used;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * Plan 6-6: the prompt version screens and their API are an administrator's; every change is a POST the console's CSRF
 * protection covers; a refusal answers 422 with the code the screens name; the addresses of the release screens open
 * the version screens.
 */
class PromptVersionConsoleControllerTest {

    private static final String PAGES = "/contexa/admin/prompt-quality/versions";
    private static final String API = "/contexa/admin/api/prompt-quality/versions";

    private final PromptVersionConsole console = mock(PromptVersionConsole.class);
    private final Authentication admin = new UsernamePasswordAuthenticationToken("admin", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    private final Authentication user = new UsernamePasswordAuthenticationToken("alice", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final HttpSessionCsrfTokenRepository csrf = new HttpSessionCsrfTokenRepository();
    private MockMvc mvc;
    private MockHttpSession session;
    private CsrfToken token;

    @BeforeEach
    void setUp() {
        // The console's filter masks the token it hands a page; the test sends it as it is, so the filter reads it plain.
        CsrfFilter filter = new CsrfFilter(csrf);
        filter.setRequestHandler(new CsrfTokenRequestAttributeHandler());
        mvc = MockMvcBuilders.standaloneSetup(new PromptVersionConsoleController(console, null, new ObjectMapper()))
                .addFilters(filter).build();
        session = new MockHttpSession();
        MockHttpServletRequest seed = new MockHttpServletRequest();
        seed.setSession(session);
        token = csrf.generateToken(seed);
        csrf.saveToken(token, seed, new MockHttpServletResponse());
        when(console.list(any(), any(), anyBoolean())).thenReturn(new ListView("PLATFORM_GLOBAL",
                List.of("PLATFORM_GLOBAL"), "cortex.security-decision",
                List.of(new PromptChoice("cortex.security-decision", true)), true, true, true,
                new Used("v1.0", "Contexa", "BUILD_DEFAULT", null, null, 0, "contexa"), new Counts(1, 1, 0, 0),
                new Running(null, null, null, null, null, null, null, null), null, List.of()));
    }

    private MockHttpServletRequestBuilder withToken(MockHttpServletRequestBuilder request) {
        return request.session(session).header(token.getHeaderName(), token.getToken());
    }

    @Test
    void theFiveScreensAreTheirTemplatesAndLightTheVersionsMenu() throws Exception {
        for (String[] screen : new String[][] {{"", "list"}, {"/2", "version"}, {"/new", "new"}, {"/trials", "trials"},
                {"/trials/7", "trials"}, {"/advanced", "advanced"}}) {
            mvc.perform(get(PAGES + screen[0]).principal(admin))
                    .andExpect(status().isOk())
                    .andExpect(view().name("contexa/admin/prompt-version/" + screen[1]))
                    .andExpect(model().attribute("activePage", "prompt-quality-versions"))
                    .andExpect(model().attribute("apiBase", API))
                    .andExpect(model().attributeExists("scriptMessagesJson"));
        }
        mvc.perform(get(PAGES + "/2").principal(admin)).andExpect(model().attribute("versionNumber", 2));
        mvc.perform(get(PAGES + "/trials/7").principal(admin)).andExpect(model().attribute("trialId", 7L));
    }

    @Test
    void theAddressesOfTheReleaseScreensOpenTheVersionScreens() throws Exception {
        mvc.perform(get("/contexa/admin/prompt-quality/releases").principal(admin))
                .andExpect(redirectedUrl(PAGES));
        mvc.perform(get("/contexa/admin/prompt-quality/releases").param("registryScope", "tenant-a").principal(admin))
                .andExpect(redirectedUrl(PAGES + "?scope=tenant-a"));
        mvc.perform(get("/contexa/admin/prompt-quality/releases/detail").param("promptKey", "cortex.security-decision")
                .param("promptVersion", "v3.0").principal(admin))
                .andExpect(redirectedUrl(PAGES + "/3?prompt=cortex.security-decision"));
        // An earlier bundle's name is no version: the list opens.
        mvc.perform(get("/contexa/admin/prompt-quality/releases/detail").param("promptVersion", "2026.10.24-v19.21")
                .principal(admin)).andExpect(redirectedUrl(PAGES));
        mvc.perform(get("/contexa/admin/prompt-quality/releases/compare").param("promptKey", "cortex.security-decision")
                .principal(admin)).andExpect(redirectedUrl(PAGES + "/trials?prompt=cortex.security-decision"));
    }

    @Test
    void someoneWhoIsNoAdministratorReadsAndChangesNothing() throws Exception {
        for (String page : List.of(PAGES, PAGES + "/2", PAGES + "/new", PAGES + "/trials", PAGES + "/advanced",
                "/contexa/admin/prompt-quality/releases")) {
            mvc.perform(get(page).principal(user)).andExpect(status().isForbidden());
        }
        for (String read : List.of(API, API + "/2", API + "/draft?base=1", API + "/2/use-check", API + "/trials",
                API + "/advanced", API + "/folder", API + "/history", API + "/shadow/results", API + "/2/export")) {
            mvc.perform(get(read).principal(user)).andExpect(status().isForbidden());
        }
        mvc.perform(withToken(post(API + "/2/use")).principal(user).contentType("application/json").content("{}"))
                .andExpect(status().isForbidden());
        verify(console, never()).use(any(), any(), anyInt(), any(), any());
    }

    /** Every change of the screens is a POST that needs the console's CSRF token (plan 3.10). */
    @Test
    void aChangeWithoutTheCsrfTokenIsRefused() throws Exception {
        for (String change : List.of(API, API + "/check", API + "/2/use", API + "/2/hide", API + "/import",
                API + "/folder/rescan", API + "/canary/start", API + "/canary/stop", API + "/shadow/start",
                API + "/shadow/stop", API + "/trials", API + "/trials/7/cancel", API + "/rollback",
                API + "/rollback/key-1/approve")) {
            mvc.perform(post(change).principal(admin).contentType("application/json").content("{}"))
                    .andExpect(status().isForbidden());
        }
        verify(console, never()).create(any(), any(), any());
        verify(console, never()).use(any(), any(), anyInt(), any(), any());
        verify(console, never()).hide(any(), any(), anyInt(), any());
    }

    @Test
    void theReadsAnswerWhatTheConsoleComposed() throws Exception {
        mvc.perform(get(API).param("prompt", "cortex.security-decision").principal(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.used.version").value("v1.0"))
                .andExpect(jsonPath("$.decisionPrompt").value(true))
                .andExpect(jsonPath("$.counts.total").value(1));
        when(console.version(any(), any(), eq(9))).thenReturn(Optional.empty());
        mvc.perform(get(API + "/9").principal(admin)).andExpect(status().isNotFound());
        when(console.export(any(), any(), eq(1), eq(false))).thenReturn(Optional.of("prompt: cortex.security-decision\n"));
        mvc.perform(get(API + "/1/export").principal(admin))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition",
                        containsString("cortex.security-decision-v1.0.yaml")));
        mvc.perform(get(API + "/1/export").param("form", "zip").principal(admin)).andExpect(status().isBadRequest());
        mvc.perform(get(API + "/shadow/results").param("days", "91").principal(admin)).andExpect(status().isBadRequest());
    }

    @Test
    void aChangeWithTheTokenIsDoneAndARefusalAnswersItsCode() throws Exception {
        when(console.use(any(), any(), eq(2), eq("admin"), eq("ready"))).thenReturn(new Receipt(true, "v2.0", "v1.0",
                "PASSED", List.of()));
        mvc.perform(withToken(post(API + "/2/use")).principal(admin).contentType("application/json")
                        .content("{\"reason\":\"ready\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.applied").value(true));

        when(console.use(any(), any(), eq(3), eq("admin"), isNull())).thenReturn(new Receipt(false, "v3.0", "v1.0",
                "BLOCKED", List.of("ILLEGAL_STATE_TRANSITION")));
        mvc.perform(withToken(post(API + "/3/use")).principal(admin).contentType("application/json").content("{}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.blockers[0]").value("ILLEGAL_STATE_TRANSITION"));

        when(console.startCanary(any(), any(), eq(2), eq(30), any(), any(), anyString(), any()))
                .thenThrow(new PromptVersionConsole.RefusedException("CANARY_PERCENT"));
        mvc.perform(withToken(post(API + "/canary/start")).principal(admin).contentType("application/json")
                        .content("{\"number\":2,\"percent\":30}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("CANARY_PERCENT"));

        when(console.create(any(), any(), eq("admin"))).thenThrow(new PromptVersionDocumentException(List.of(
                new PromptVersionProblem(PromptVersionProblem.Code.LOCKED_PART, "system.mission", null))));
        mvc.perform(withToken(post(API)).principal(admin).contentType("application/json")
                        .content("{\"prompt\":\"cortex.security-decision\",\"base\":1}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("PROBLEMS"))
                .andExpect(jsonPath("$.problems[0].code").value("LOCKED_PART"))
                .andExpect(jsonPath("$.problems[0].where").value("system.mission"));

        when(console.startTrial(any(), any(), eq(2), eq(1), eq(20), eq("admin")))
                .thenThrow(new PromptVersionTrials.RefusedException(PromptVersionTrials.Refusal.NO_SEALED_DECISIONS));
        mvc.perform(withToken(post(API + "/trials")).principal(admin).contentType("application/json")
                        .content("{\"candidate\":2,\"reference\":1,\"count\":20}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("TRIAL_NO_SEALED_DECISIONS"));

        when(console.importDocument(any(), eq("org.yaml"), eq("prompt: x"), eq("admin")))
                .thenReturn(new Created(4, "v4.0", "hash", true, null));
        mvc.perform(withToken(post(API + "/import")).principal(admin).contentType("application/json")
                        .content("{\"fileName\":\"org.yaml\",\"text\":\"prompt: x\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("v4.0"));

        when(console.emergencyRollback(any(), any(), eq(1), eq("bad answers"), eq("admin")))
                .thenReturn(new PromptBundleRollbackService.Result("key-1", PromptBundleRollbackService.REFUSED, null,
                        List.of("REASON_REQUIRED")));
        mvc.perform(withToken(post(API + "/rollback")).principal(admin).contentType("application/json")
                        .content("{\"number\":1,\"reason\":\"bad answers\"}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.refusals[0]").value("REASON_REQUIRED"));

        mvc.perform(withToken(post(API + "/canary/start")).principal(admin).contentType("application/json")
                .content("{}")).andExpect(status().isBadRequest());
    }
}
