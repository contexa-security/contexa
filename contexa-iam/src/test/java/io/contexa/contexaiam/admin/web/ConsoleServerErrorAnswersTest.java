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
package io.contexa.contexaiam.admin.web;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacore.autonomous.agent.AgentLearningControl;
import io.contexa.contexacore.autonomous.baseline.store.InMemoryBaselineDataStore;
import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexaiam.admin.web.agent.controller.AgentLearningApiController;
import io.contexa.contexaiam.admin.web.agent.controller.LearningActionRequest;
import io.contexa.contexaiam.admin.web.agent.controller.LearningActionResponse;
import io.contexa.contexaiam.admin.web.agent.service.AgentLearningAdminService;
import io.contexa.contexaiam.admin.web.auth.controller.BlacklistApiController;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.admin.web.center.PolicyCenterOperationsController;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterPolicyRequest;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterAnalysisService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterCommandService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterQueryService;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.controller.ConditionClassificationController;
import io.contexa.contexaiam.resource.service.AutoConditionTemplateService;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * What an administrator's request that fails with a server fault answers: that it failed, and not the exception's text,
 * which names what failed inside (a connection, a statement, a class). The text is the operators', in the log, where
 * the exception is kept. The status, the fields and the answers of the requests the application refuses are as they
 * were.
 */
class ConsoleServerErrorAnswersTest {

    private static final String INTERNAL_CAUSE = "jdbc:postgresql://db.internal:5432/contexa refused the connection";

    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final List<Logger> listened = new ArrayList<>();

    @BeforeEach
    void signIn() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("admin-1", null, List.of()));
        logged.start();
        for (Class<?> type : List.of(AgentLearningApiController.class, BlacklistApiController.class,
                ConditionClassificationController.class, PolicyCenterOperationsController.class)) {
            Logger logger = (Logger) LoggerFactory.getLogger(type);
            logger.addAppender(logged);
            listened.add(logger);
        }
    }

    @AfterEach
    void signOut() {
        SecurityContextHolder.clearContext();
        listened.forEach(logger -> logger.detachAppender(logged));
    }

    @Test
    @DisplayName("an agent learning action that fails is a 500 that says the action could not be completed, not why")
    void aFailedLearningActionDoesNotTellWhy() {
        PastRecordQuery records = mock(PastRecordQuery.class);
        when(records.quarantineAgentRecords("agt-1", null)).thenThrow(new RuntimeException(INTERNAL_CAUSE));
        AgentLearningApiController controller = new AgentLearningApiController(new AgentLearningAdminService(
                new AgentLearningControl(new InMemorySecurityContextDataStore(),
                        new InMemoryBaselineDataStore(Duration.ofDays(30)), () -> records), null));

        ResponseEntity<LearningActionResponse> answer = controller.act(
                new LearningActionRequest("agt-1", null, "QUARANTINE", "reviewed"));

        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(answer.getBody().success()).isFalse();
        assertThat(answer.getBody().error()).isNotBlank().doesNotContain(INTERNAL_CAUSE);
        assertThat(answer.getBody().agentId()).isNull();
        assertTheLogKeepsTheCause();
    }

    @Test
    @DisplayName("the learning action's own refusals keep saying why")
    void aRefusedLearningActionStillSaysWhy() {
        AgentLearningApiController controller = new AgentLearningApiController(new AgentLearningAdminService(
                new AgentLearningControl(new InMemorySecurityContextDataStore(),
                        new InMemoryBaselineDataStore(Duration.ofDays(30)), () -> mock(PastRecordQuery.class)), null));

        ResponseEntity<LearningActionResponse> answer = controller.act(
                new LearningActionRequest("agt-1", null, "forget", "reviewed"));

        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(answer.getBody().error()).contains("forget");
    }

    @Test
    @DisplayName("a block that cannot be resolved because of a server fault is a 500 that does not tell why")
    void aFailedResolveDoesNotTellWhy() throws Exception {
        BlockedUserService blocks = mock(BlockedUserService.class);
        doThrow(new RuntimeException(INTERNAL_CAUSE)).when(blocks).resolveBlockById(7L, "admin-1", "ALLOW", "verified");

        MvcResult result = blacklist(blocks).perform(post("/contexa/admin/api/blacklist/7/resolve")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"resolvedAction\":\"ALLOW\",\"reason\":\"verified\"}"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error").isNotEmpty())
                .andExpect(jsonPath("$.id").doesNotExist())
                .andReturn();

        assertThat(body(result)).doesNotContain(INTERNAL_CAUSE);
        assertTheLogKeepsTheCause();
    }

    @Test
    @DisplayName("a block record that cannot be deleted because of a server fault is a 500 that does not tell why")
    void aFailedDeleteDoesNotTellWhy() throws Exception {
        BlockedUserService blocks = mock(BlockedUserService.class);
        doThrow(new RuntimeException(INTERNAL_CAUSE)).when(blocks).deleteBlockRecord(8L, "admin-1");

        MvcResult result = blacklist(blocks).perform(delete("/contexa/admin/api/blacklist/8"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error").isNotEmpty())
                .andExpect(jsonPath("$.id").doesNotExist())
                .andReturn();

        assertThat(body(result)).doesNotContain(INTERNAL_CAUSE);
        assertTheLogKeepsTheCause();
    }

    @Test
    @DisplayName("the refusals of the block record still say why: a record in force is a 409, a missing one a 404")
    void theRefusalsOfTheRecordStillSayWhy() throws Exception {
        BlockedUserService blocks = mock(BlockedUserService.class);
        doThrow(new IllegalStateException("Cannot delete active block. Resolve first: id=7"))
                .when(blocks).deleteBlockRecord(7L, "admin-1");
        doThrow(new IllegalArgumentException("Blocked user not found: id=9"))
                .when(blocks).deleteBlockRecord(9L, "admin-1");
        MockMvc mvc = blacklist(blocks);

        mvc.perform(delete("/contexa/admin/api/blacklist/7")).andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("Cannot delete active block. Resolve first: id=7"));
        mvc.perform(delete("/contexa/admin/api/blacklist/9")).andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("Blocked user not found: id=9"));
    }

    @Test
    @DisplayName("a condition template generation that fails is a 500 whose error is not the exception's text")
    void aFailedTemplateGenerationDoesNotTellWhy() throws Exception {
        AutoConditionTemplateService generation = mock(AutoConditionTemplateService.class);
        when(generation.generateConditionTemplates()).thenThrow(new RuntimeException(INTERNAL_CAUSE));
        ManagedResourceRepository resources = mock(ManagedResourceRepository.class);
        when(resources.count()).thenReturn(3L);
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new ConditionClassificationController(
                mock(ConditionTemplateRepository.class), resources, mock(ConditionCompatibilityService.class),
                generation)).build();

        for (String path : List.of("regenerate-fixed-templates", "generate-managed-resource-based",
                "generate-permission-based")) {
            MvcResult result = mvc.perform(post("/contexa/admin/api/conditions/" + path))
                    .andExpect(status().isInternalServerError())
                    .andExpect(jsonPath("$.success").value(false))
                    .andExpect(jsonPath("$.error").isNotEmpty())
                    .andExpect(jsonPath("$.message").value(startsWith("An error occurred while")))
                    .andReturn();

            assertThat(body(result)).as(path).doesNotContain(INTERNAL_CAUSE);
        }
        assertTheLogKeepsTheCause();
    }

    @Test
    @DisplayName("the analysis of a policy's impact that fails is a 500 that does not carry the exception")
    void aFailedImpactAnalysisDoesNotTellWhy() throws Exception {
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setDefaultEncoding(StandardCharsets.UTF_8.name());
        PolicyCenterAnalysisService analysis = mock(PolicyCenterAnalysisService.class);
        when(analysis.analyzeImpact(any(PolicyCenterPolicyRequest.class))).thenThrow(new RuntimeException(INTERNAL_CAUSE));
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new PolicyCenterOperationsController(messages,
                mock(PolicyCenterQueryService.class), mock(PolicyCenterCommandService.class), analysis)).build();

        MvcResult result = mvc.perform(post("/contexa/admin/policy-center/api/impact-analysis")
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").isNotEmpty())
                .andReturn();

        assertThat(body(result)).doesNotContain(INTERNAL_CAUSE);
        assertTheLogKeepsTheCause();
    }

    private MockMvc blacklist(BlockedUserService blocks) {
        return MockMvcBuilders.standaloneSetup(new BlacklistApiController(blocks, new StaticMessageSource())).build();
    }

    private static String body(MvcResult result) throws Exception {
        return result.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private void assertTheLogKeepsTheCause() {
        assertThat(logged.list).anySatisfy(event -> {
            assertThat(event.getThrowableProxy()).isNotNull();
            assertThat(event.getThrowableProxy().getMessage()).isEqualTo(INTERNAL_CAUSE);
        });
    }
}
