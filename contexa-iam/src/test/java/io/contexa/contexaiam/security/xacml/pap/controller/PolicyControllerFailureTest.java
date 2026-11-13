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
package io.contexa.contexaiam.security.xacml.pap.controller;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexaiam.common.GlobalExceptionHandler;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.modelmapper.ModelMapper;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

/**
 * D01: a policy that is not there, an edit the service refuses and a form that cannot be bound went to a server error
 * or to the list without the cause; they go back to the screen they came from with it. D13: a refusal is logged as a
 * warning without a stack, a fault as an error with it.
 */
@ExtendWith(I18nTestSupport.EnglishLocale.class)
class PolicyControllerFailureTest {

    private final MessageSource messages = I18nTestSupport.englishMessageSource();
    private final PolicyService policies = mock(PolicyService.class);
    private final PolicyController controller = new PolicyController(policies, mock(ModelMapper.class), messages);

    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger(PolicyController.class);

    @BeforeEach
    void listen() {
        logged.start();
        logger.addAppender(logged);
    }

    @AfterEach
    void stopListening() {
        logger.detachAppender(logged);
    }

    @Test
    @DisplayName("a policy that is not there goes back to the list with the reason, logged as a warning")
    void aPolicyThatIsNotThereGoesBackToTheList() {
        when(policies.findPolicy(999999L)).thenReturn(Optional.empty());
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = controller.detailForm(999999L, new ExtendedModelMap(), flash);

        assertThat(view).isEqualTo("redirect:/contexa/admin/policy-center?tab=list");
        assertThat(String.valueOf(flash.getFlashAttributes().get("errorMessage"))).contains("999999")
                .doesNotContain("999,999");
        verify(policies, never()).findById(any());
        assertThat(logged.list).allSatisfy(event -> assertThat(event.getLevel()).isEqualTo(Level.WARN));
    }

    @Test
    @DisplayName("a refused edit goes back to the policy's screen with the reason and what was typed")
    void aRefusedEditGoesBackToTheDetailScreen() {
        doThrow(new IllegalArgumentException("Policy name can be at most 255 characters (256 entered)."))
                .when(policies).updatePolicy(any());
        PolicyDto typed = PolicyDto.builder().name("n".repeat(256)).effect(Policy.Effect.ALLOW).build();
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = controller.updatePolicy(8L, typed, flash);

        assertThat(view).isEqualTo("redirect:/contexa/admin/policies/8");
        assertThat(String.valueOf(flash.getFlashAttributes().get("errorMessage"))).contains("at most 255");
        assertThat(flash.getFlashAttributes().get("typedPolicy")).isSameAs(typed);
        assertThat(logged.list).hasSize(1);
        assertThat(logged.list.get(0).getLevel()).isEqualTo(Level.WARN);
        assertThat(logged.list.get(0).getThrowableProxy()).isNull();

        ExtendedModelMap model = new ExtendedModelMap();
        model.addAttribute("typedPolicy", typed);
        Policy stored = Policy.builder().id(8L).name("stored").effect(Policy.Effect.DENY).build();
        PolicyRule rule = PolicyRule.builder().build();
        rule.addCondition(PolicyCondition.builder().expression("hasRole('USER')").build());
        stored.addRule(rule);
        when(policies.findPolicy(8L)).thenReturn(Optional.of(stored));
        controller.detailForm(8L, model, new RedirectAttributesModelMap());
        assertThat(((PolicyDto) model.getAttribute("policy")).getName()).isEqualTo(typed.getName());
    }

    @Test
    @DisplayName("a fault of the server is logged as an error with its stack, and told in general words")
    void aFaultIsLoggedAsAnError() {
        doThrow(new RuntimeException("connection reset")).when(policies).updatePolicy(any());
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        controller.updatePolicy(8L, new PolicyDto(), flash);

        assertThat(String.valueOf(flash.getFlashAttributes().get("errorMessage"))).doesNotContain("connection reset");
        assertThat(logged.list).hasSize(1);
        assertThat(logged.list.get(0).getLevel()).isEqualTo(Level.ERROR);
        assertThat(logged.list.get(0).getThrowableProxy()).isNotNull();
    }

    @Test
    @DisplayName("a form that cannot be bound goes back to the screen it came from instead of a server error")
    void aFormThatCannotBeBoundGoesBack() throws Exception {
        MockMvc mvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler()).build();

        mvc.perform(post("/contexa/admin/policies/8/edit").param("effect", "MAYBE").param("priority", "high"))
                .andExpect(redirectedUrl("/contexa/admin/policies/8"))
                .andExpect(flash().attribute("errorMessage", containsString("effect")));
        mvc.perform(post("/contexa/admin/policies").param("priority", "high"))
                .andExpect(redirectedUrl("/contexa/admin/policy-center?tab=list"));

        verify(policies, never()).updatePolicy(any());
        verify(policies, never()).createPolicy(any());
    }
}
