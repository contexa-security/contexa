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
package io.contexa.contexaiam.admin.web.monitoring.controller;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationAuditReason;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.spring6.view.ThymeleafViewResolver;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import java.time.LocalDateTime;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * D29: the URL authorization kept its reason as the English sentence "Static rule matching", and the Korean security
 * monitor showed it as it was. The reason is kept as a code and shown in the language of the screen; the sentences kept
 * before are shown the same way, and a reason written by anything else is shown as it was stored.
 */
class SecurityMonitorReasonScreenTest {

    private final AuditLogRepository auditLogs = mock(AuditLogRepository.class);
    private MockMvc mvc;

    @BeforeEach
    void aConsole() {
        ThymeleafViewResolver views = new ThymeleafViewResolver();
        views.setTemplateEngine(engine());
        views.setCharacterEncoding("UTF-8");
        mvc = MockMvcBuilders.standaloneSetup(new SecurityMonitorController(auditLogs, mock(CsvExportService.class)))
                .setViewResolvers(views)
                .build();
    }

    @ParameterizedTest
    @ValueSource(strings = {AuthorizationAuditReason.STATIC_RULE, "Static rule matching"})
    @DisplayName("the static rule reason, new code or old sentence, reads in Korean on the Korean screen")
    void theStaticRuleReasonIsShownInTheScreensLanguage(String stored) throws Exception {
        String korean = page(stored, Locale.KOREAN);
        String english = page(stored, Locale.ENGLISH);

        assertThat(korean).contains("정적 규칙 일치").doesNotContain("Static rule matching")
                .doesNotContain(AuthorizationAuditReason.STATIC_RULE);
        assertThat(english).contains("Static rule matching (decided by the URL policies)");
    }

    @ParameterizedTest
    @ValueSource(strings = {"AUTHZ_AI_ASSESSMENT {\"score\":0.4}", "AI assessment result: {\"score\":0.4}"})
    @DisplayName("an AI assessment reason, new code or old sentence, keeps the assessment and reads in Korean")
    void anAiAssessmentReasonIsShownInTheScreensLanguage(String stored) throws Exception {
        assertThat(page(stored, Locale.KOREAN)).contains("AI 평가 결과: {&quot;score&quot;:0.4}")
                .doesNotContain("AI assessment result");
    }

    @Test
    @DisplayName("a reason written by anything else is shown as stored")
    void anyOtherReasonIsShownAsStored() throws Exception {
        assertThat(page("Blocked by an administrator", Locale.KOREAN)).contains("Blocked by an administrator");
    }

    @Test
    @DisplayName("the old sentence of an assessment that could not be written is read as the same reason")
    void theUnreadableAssessmentIsReadToo() {
        assertThat(AuthorizationAuditReason.describe("AI assessment result serialization failed. Score: 0.25"))
                .isEqualTo(new AuthorizationAuditReason.Display(
                        "admin.security.monitor.reason.ai.assessment.unreadable", "0.25"));
        assertThat(AuthorizationAuditReason.describe("AUTHZ_AI_ASSESSMENT_UNREADABLE 0.25"))
                .isEqualTo(new AuthorizationAuditReason.Display(
                        "admin.security.monitor.reason.ai.assessment.unreadable", "0.25"));
        assertThat(AuthorizationAuditReason.describe(null)).isNull();
    }

    private String page(String reason, Locale locale) throws Exception {
        AuditLog record = AuditLog.builder().id(5L).eventCategory("AUTHORIZATION_DENIED").principalName("alice")
                .decision("DENY").outcome("DENIED").reason(reason).timestamp(LocalDateTime.now()).build();
        when(auditLogs.findById(5L)).thenReturn(Optional.of(record));
        return mvc.perform(get("/contexa/admin/security-monitor/5").locale(locale)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    private static ResourceBundleMessageSource messages() {
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setDefaultEncoding("UTF-8");
        messages.setFallbackToSystemLocale(false);
        return messages;
    }

    private static SpringTemplateEngine engine() {
        ClassLoaderTemplateResolver fragments = resolver("test-templates/", 1);
        fragments.setResolvablePatterns(Set.of("contexa/fragments/*"));
        ClassLoaderTemplateResolver templates = resolver("templates/", 2);
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolvers(Set.of(fragments, templates));
        engine.setTemplateEngineMessageSource(messages());
        return engine;
    }

    private static ClassLoaderTemplateResolver resolver(String prefix, int order) {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix(prefix);
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        resolver.setOrder(order);
        resolver.setCheckExistence(true);
        return resolver;
    }
}
