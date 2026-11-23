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
package io.contexa.contexaiam.admin.web.zerotrust;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.BreachConfirmed;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.DecisionDetail;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Quality plan 3.6: in the decision detail, an allowed request later found a breach is kept as the outcome of its
 * request's decision, once (a second record returns the first), with the administrator's note; a decision that did not
 * allow is refused, one that is not there is not found, and it is an administrator's alone. The detail carries the
 * words of the answer of a case and the parts of the confirmation its new buttons open.
 */
class ZeroTrustDecisionCaseTest {

    private static final String BREACH = "/contexa/admin/api/zero-trust/decisions/obs-1/breach";
    private final ZeroTrustDecisionRecords records = mock(ZeroTrustDecisionRecords.class);
    private final ZeroTrustConsoleService service = new ZeroTrustConsoleService(() -> null, null, null, null, () -> null,
            false, Clock.fixed(Instant.parse("2026-11-22T10:30:00Z"), ZoneOffset.UTC));
    private final Authentication admin = new UsernamePasswordAuthenticationToken("admin", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    private final Authentication user = new UsernamePasswordAuthenticationToken("alice", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final MockMvc mvc;

    ZeroTrustDecisionCaseTest() {
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setDefaultEncoding("UTF-8");
        messages.setFallbackToSystemLocale(false);
        mvc = MockMvcBuilders.standaloneSetup(new ZeroTrustConsoleController(service, records, messages,
                new ObjectMapper())).build();
    }

    private DecisionDetail detail(String requestId) {
        DecisionDetail detail = mock(DecisionDetail.class);
        when(detail.requestId()).thenReturn(requestId);
        return detail;
    }

    @Test
    void anAllowedRequestFoundABreachIsKeptOnceWithItsNote() throws Exception {
        DecisionDetail detail = detail("req-1");
        when(records.detail(eq("obs-1"), any())).thenReturn(detail);
        when(records.confirmBreach("req-1", "found in the audit", "admin")).thenReturn(new BreachConfirmed("outcome-1",
                "obs-1", "req-1", false));

        mvc.perform(post(BREACH).principal(admin).contentType("application/json")
                        .content("{\"note\":\"found in the audit\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.outcomeId").value("outcome-1"))
                .andExpect(jsonPath("$.already").value(false));

        when(records.confirmBreach(eq("req-1"), isNull(), eq("admin"))).thenReturn(new BreachConfirmed("outcome-1",
                "obs-1", "req-1", true));
        mvc.perform(post(BREACH).principal(admin).contentType("application/json").content("{}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.already").value(true));
    }

    @Test
    void aDecisionThatDidNotAllowIsRefusedAndOneNotThereIsNotFound() throws Exception {
        DecisionDetail detail = detail("req-2");
        when(records.detail(eq("obs-1"), any())).thenReturn(detail);
        when(records.confirmBreach(eq("req-2"), any(), anyString())).thenThrow(new IllegalArgumentException(
                "Only a decision that allowed the request is confirmed as a breach"));
        mvc.perform(post(BREACH).principal(admin).contentType("application/json").content("{}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("BREACH_NOT_ALLOWED"));

        mvc.perform(post("/contexa/admin/api/zero-trust/decisions/obs-9/breach").principal(admin)
                .contentType("application/json").content("{}")).andExpect(status().isNotFound());
        DecisionDetail without = detail(null);
        when(records.detail(eq("obs-3"), any())).thenReturn(without);
        mvc.perform(post("/contexa/admin/api/zero-trust/decisions/obs-3/breach").principal(admin)
                .contentType("application/json").content("{}")).andExpect(status().isNotFound());
    }

    @Test
    void aBreachIsAnAdministratorsAlone() throws Exception {
        mvc.perform(post(BREACH).principal(user).contentType("application/json").content("{}"))
                .andExpect(status().isForbidden());
        verify(records, never()).confirmBreach(anyString(), any(), anyString());
    }

    /** The detail's words carry the answer of a case; the other screens keep the console's own words. */
    @Test
    @SuppressWarnings("unchecked")
    void theDetailCarriesTheWordsAndThePartsOfItsNewButtons() throws Exception {
        MvcResult detailPage = mvc.perform(get("/contexa/admin/zero-trust/decisions/obs-1").principal(admin)
                .locale(Locale.KOREAN)).andReturn();
        Map<String, String> words = new ObjectMapper().readValue((String) detailPage.getModelAndView().getModel()
                .get("scriptMessagesJson"), Map.class);
        assertThat(words).containsEntry("pqa.answer.allowed", "정답(허용되는 조치)")
                .containsEntry("zt.console.ui.decision.case.choice", "이 판정을 정답 사례로도 올리기")
                .containsEntry("zt.console.ui.decision.laterBreach.button", "허용 뒤 침해로 확인")
                .containsEntry("pqa.cases.detail.privacy", "개인 정보")
                .containsKey("pqa.cases.detail.privacyLine");
        MvcResult overview = mvc.perform(get("/contexa/admin/zero-trust").principal(admin).locale(Locale.KOREAN))
                .andReturn();
        assertThat((String) overview.getModelAndView().getModel().get("scriptMessagesJson"))
                .doesNotContain("pqa.answer.");

        String template = new ClassPathResource("templates/contexa/admin/zero-trust/decision.html")
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(template).contains("id=\"pqa-confirm-overlay\"")
                .contains("/contexa/js/admin/prompt-quality/pqa-parts.js?v=20261122-s3")
                .contains("/contexa/js/admin/prompt-quality/case-answer.js?v=20261123-sup3")
                .contains("/contexa/js/admin/zero-trust/decision.js?v=20261123-sup3");
        assertThat(template.indexOf("case-answer.js")).isLessThan(template.indexOf("decision.js"));
    }

    @Test
    void theWordsOfTheNewButtonsAreInBothLanguages() throws IOException {
        Properties english = new Properties();
        Properties korean = new Properties();
        english.load(new InputStreamReader(new ClassPathResource("contexa/i18n/messages.properties")
                .getInputStream(), StandardCharsets.UTF_8));
        korean.load(new InputStreamReader(new ClassPathResource("contexa/i18n/messages_ko.properties")
                .getInputStream(), StandardCharsets.UTF_8));
        Set<String> keys = new TreeSet<>();
        english.stringPropertyNames().stream().filter(key -> key.startsWith("zt.console.ui.decision.case.")
                || key.startsWith("zt.console.ui.decision.laterBreach.")).forEach(keys::add);
        assertThat(keys).hasSizeGreaterThan(20);
        assertThat(keys).allSatisfy(key -> assertThat(korean.getProperty(key)).as(key).isNotBlank()
                .isNotEqualTo(english.getProperty(key)));
    }
}
