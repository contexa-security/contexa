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
package io.contexa.autoconfigure.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.protocol.request.ConditionTemplateGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.properties.IamAdminProperties;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.resource.controller.ConditionClassificationController;
import io.contexa.contexaiam.resource.service.AutoConditionTemplateService;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * K119: the condition templates' administration API (seven endpoints under /contexa/admin/api/conditions) is registered
 * by the starter, as every console controller is, rather than left to a component scan it never runs: a servlet
 * application gets it beside the services it calls, an application of its own keeps its own, administrators alone
 * reach it, a change needs the CSRF token, and a generation asks the condition template prompt.
 */
class ConditionClassificationApiTest {

    private static final String API = "/contexa/admin/api/conditions";

    private AnnotationConfigWebApplicationContext context;

    @AfterEach
    void close() {
        if (context != null) {
            context.close();
        }
    }

    // ----- the registration -----

    @Test
    @DisplayName("K119: a servlet application gets the API as contexaConditionClassificationController")
    void aServletApplicationGetsTheApi() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(IamResourceAutoConfiguration.class))
                .withUserConfiguration(Dependencies.class)
                .run(started -> {
                    assertThat(started).hasNotFailed();
                    assertThat(started).hasSingleBean(ConditionClassificationController.class);
                    assertThat(started).hasBean("contexaConditionClassificationController");
                });
    }

    @Test
    @DisplayName("K119: an application without a servlet web layer gets no controller, its services still")
    void anApplicationWithoutAServletWebLayerGetsNoController() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(IamResourceAutoConfiguration.class))
                .withUserConfiguration(Dependencies.class)
                .run(started -> {
                    assertThat(started).hasNotFailed();
                    assertThat(started).doesNotHaveBean(ConditionClassificationController.class);
                    assertThat(started).hasSingleBean(AutoConditionTemplateService.class);
                });
    }

    @Test
    @DisplayName("K119: an application's own controller of the API is kept, the starter's backs off")
    void anApplicationsOwnControllerIsKept() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(IamResourceAutoConfiguration.class))
                .withUserConfiguration(Dependencies.class, OwnController.class)
                .run(started -> {
                    assertThat(started).hasNotFailed();
                    assertThat(started).hasSingleBean(ConditionClassificationController.class);
                    assertThat(started).hasBean("ownConditionClassificationController")
                            .doesNotHaveBean("contexaConditionClassificationController");
                });
    }

    @Test
    @DisplayName("K119: the API keeps its address and its administrators-only rule")
    void theApiKeepsItsAddressAndItsRule() {
        assertThat(ConditionClassificationController.class.getAnnotation(RequestMapping.class).value())
                .containsExactly(API);
        assertThat(ConditionClassificationController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo("hasAuthority('ROLE_ADMIN')");
    }

    // ----- the requests -----

    @Test
    @DisplayName("K119: an administrator reads the classified conditions, another account is refused (403)")
    void anAdministratorReadsAnotherAccountIsRefused() throws Exception {
        MockMvc mvc = start();
        when(Mocks.TEMPLATES.findAll()).thenReturn(List.of(ConditionTemplate.builder().id(1L).name("Own resource")
                .spelTemplate("#isOwner(#id)").classification(ConditionTemplate.ConditionClassification.UNIVERSAL)
                .build()));

        mvc.perform(get(API + "/classified").with(user("admin").authorities(() -> "ROLE_ADMIN")))
                .andExpect(status().isOk());
        mvc.perform(get(API + "/classified").with(user("staff").authorities(() -> "ROLE_USER")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("K119: a change needs the CSRF token, an administrator's change with it is saved")
    void aChangeNeedsTheCsrfToken() throws Exception {
        MockMvc mvc = start();
        ConditionTemplate condition = ConditionTemplate.builder().id(7L).name("Business hours")
                .spelTemplate("#isBusinessHours()").classification(ConditionTemplate.ConditionClassification.UNIVERSAL)
                .build();
        when(Mocks.TEMPLATES.findById(7L)).thenReturn(Optional.of(condition));
        String body = "{\"classification\":\"CONTEXT_DEPENDENT\",\"approvalRequired\":true,\"contextDependent\":true}";

        mvc.perform(put(API + "/7/classification").with(user("admin").authorities(() -> "ROLE_ADMIN"))
                        .contentType("application/json").content(body))
                .andExpect(status().isForbidden());
        verify(Mocks.TEMPLATES, never()).save(any());

        mvc.perform(put(API + "/7/classification").with(user("admin").authorities(() -> "ROLE_ADMIN")).with(csrf())
                        .contentType("application/json").content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.newClassification").value("CONTEXT_DEPENDENT"));
        verify(Mocks.TEMPLATES).save(condition);
        mvc.perform(put(API + "/7/classification").with(user("staff").authorities(() -> "ROLE_USER")).with(csrf())
                        .contentType("application/json").content(body))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("K119: a generation through the API asks the condition template prompt, universal and per method")
    void aGenerationAsksTheConditionTemplatePrompt() throws Exception {
        MockMvc mvc = start();
        when(Mocks.RESOURCES.findByResourceType(ManagedResource.ResourceType.METHOD)).thenReturn(List.of(
                ManagedResource.builder().id(3L).resourceIdentifier("com.example.OrderService.cancel(java.lang.Long)")
                        .resourceType(ManagedResource.ResourceType.METHOD).parameterTypes("[java.lang.Long]")
                        .serviceOwner("orders").build()));
        when(Mocks.AI.process(any(), eq(ConditionTemplateGenerationResponse.class))).thenReturn(Mono.empty());

        mvc.perform(post(API + "/generate-managed-resource-based").with(user("admin").authorities(() -> "ROLE_ADMIN"))
                        .with(csrf()))
                .andExpect(status().isOk());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<AIRequest<ConditionTemplateContext>> asked = ArgumentCaptor.forClass(AIRequest.class);
        verify(Mocks.AI, atLeastOnce()).process(asked.capture(), eq(ConditionTemplateGenerationResponse.class));
        assertThat(asked.getAllValues()).allSatisfy(request -> {
            assertThat(request).isInstanceOf(ConditionTemplateGenerationRequest.class);
            assertThat(request.getPromptTemplate().name()).isEqualTo("ConditionTemplate");
        });
        assertThat(asked.getAllValues()).extracting(request -> request.getContext().getTemplateType())
                .containsExactlyInAnyOrder("universal", "specific");
    }

    /** A servlet context of the auto-configuration's controller behind a filter chain and method security. */
    private MockMvc start() {
        Mocks.reset();
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.register(Web.class);
        context.refresh();
        return MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    /** The mocks the configurations share, made anew for each request test. */
    static final class Mocks {
        static ConditionTemplateRepository TEMPLATES;
        static ManagedResourceRepository RESOURCES;
        static AICoreOperations<ConditionTemplateContext> AI;

        @SuppressWarnings("unchecked")
        static void reset() {
            TEMPLATES = mock(ConditionTemplateRepository.class);
            RESOURCES = mock(ManagedResourceRepository.class);
            AI = mock(AICoreOperations.class);
        }

        private Mocks() {
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    @EnableMethodSecurity
    static class Web {

        @Bean
        SecurityFilterChain chain(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated()).build();
        }

        @Bean
        ConditionClassificationController contexaConditionClassificationController() {
            IamResourceAutoConfiguration configuration = new IamResourceAutoConfiguration();
            return configuration.conditionClassificationController(Mocks.TEMPLATES, Mocks.RESOURCES,
                    configuration.conditionCompatibilityService(),
                    configuration.autoConditionTemplateService(Mocks.TEMPLATES, Mocks.RESOURCES, Mocks.AI));
        }
    }

    /** What IamResourceAutoConfiguration's beans read from the rest of the starter. */
    @Configuration(proxyBeanMethods = false)
    static class Dependencies {

        @Bean
        ConditionTemplateRepository conditionTemplateRepository() {
            return mock(ConditionTemplateRepository.class);
        }

        @Bean
        ManagedResourceRepository managedResourceRepository() {
            return mock(ManagedResourceRepository.class);
        }

        @Bean
        PolicyRepository policyRepository() {
            return mock(PolicyRepository.class);
        }

        @Bean
        PermissionCatalogService contexaPermissionCatalogService() {
            return mock(PermissionCatalogService.class);
        }

        @Bean
        @SuppressWarnings("unchecked")
        AICoreOperations<ConditionTemplateContext> contexaAiNativeProcessor() {
            return mock(AICoreOperations.class);
        }

        @Bean
        IamAdminProperties iamAdminProperties() {
            return new IamAdminProperties();
        }

        @Bean
        ObjectMapper contexaObjectMapper() {
            return new ObjectMapper();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class OwnController {

        @Bean
        ConditionClassificationController ownConditionClassificationController(
                ConditionTemplateRepository conditionTemplateRepository,
                ManagedResourceRepository managedResourceRepository) {
            return new ConditionClassificationController(conditionTemplateRepository, managedResourceRepository,
                    new ConditionCompatibilityService(), mock(AutoConditionTemplateService.class));
        }
    }
}
