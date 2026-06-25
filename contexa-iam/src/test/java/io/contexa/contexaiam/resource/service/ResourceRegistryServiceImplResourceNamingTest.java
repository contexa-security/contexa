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
package io.contexa.contexaiam.resource.service;

import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingSuggestionResponse;
import io.contexa.contexaiam.properties.IamAdminProperties;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.springframework.context.support.StaticMessageSource;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("ResourceRegistryServiceImpl resource naming suggestions")
class ResourceRegistryServiceImplResourceNamingTest {

    private ManagedResourceRepository managedResourceRepository;
    private AICoreOperations<ResourceNamingContext> aiNativeProcessor;
    private ResourceRegistryServiceImpl service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        managedResourceRepository = mock(ManagedResourceRepository.class);
        aiNativeProcessor = mock(AICoreOperations.class);
        service = new ResourceRegistryServiceImpl(
                List.of(),
                managedResourceRepository,
                mock(PermissionCatalogService.class),
                aiNativeProcessor,
                mock(AutoConditionTemplateService.class),
                mock(PolicyRepository.class),
                new IamAdminProperties(),
                new StaticMessageSource());
    }

    @Test
    @DisplayName("Valid LLM response updates only the matching managed resource")
    @SuppressWarnings({"unchecked", "rawtypes"})
    void processResourceBatch_appliesMatchingSuggestionAndSendsServerContext() {
        ManagedResource resource = ManagedResource.builder()
                .resourceIdentifier("/contexa/admin/users")
                .resourceType(ManagedResource.ResourceType.URL)
                .httpMethod(ManagedResource.HttpMethod.GET)
                .friendlyName("listUsers")
                .description("URL: [GET] /contexa/admin/users")
                .serviceOwner("UserController")
                .apiDocsUrl("/docs#users")
                .build();
        ResourceNamingSuggestionResponse response = new ResourceNamingSuggestionResponse(
                List.of(ResourceNamingSuggestionResponse.ResourceNamingSuggestion.builder()
                        .identifier("/contexa/admin/users")
                        .friendlyName("User Accounts")
                        .description("Manage user account records.")
                        .confidence(0.93)
                        .build()),
                List.of());
        when(aiNativeProcessor.process(ArgumentMatchers.<AIRequest<ResourceNamingContext>>any(), eq(ResourceNamingSuggestionResponse.class)))
                .thenReturn(Mono.just(response));

        service.processResourceBatch(List.of(resource));

        assertThat(resource.getFriendlyName()).isEqualTo("User Accounts");
        assertThat(resource.getDescription()).isEqualTo("Manage user account records.");
        ArgumentCaptor<AIRequest> requestCaptor = ArgumentCaptor.forClass(AIRequest.class);
        verify(aiNativeProcessor).process(requestCaptor.capture(), eq(ResourceNamingSuggestionResponse.class));
        List<Map<String, String>> resources = (List<Map<String, String>>) requestCaptor.getValue().getParameter("resources", List.class);
        assertThat(resources).hasSize(1);
        assertThat(resources.get(0))
                .containsEntry("identifier", "/contexa/admin/users")
                .containsEntry("resourceType", "URL")
                .containsEntry("httpMethod", "GET")
                .containsEntry("owner", "UserController")
                .containsEntry("scannerFriendlyNameHint", "listUsers")
                .containsEntry("scannerDescriptionHint", "URL: [GET] /contexa/admin/users")
                .containsEntry("apiDocsUrl", "/docs#users");
    }

    @Test
    @DisplayName("Stats-only LLM response never creates a stats suggestion")
    void processResourceBatch_ignoresStatsOnlyResponseAndFallsBackResource() {
        ManagedResource resource = ManagedResource.builder()
                .resourceIdentifier("/contexa/admin/users")
                .resourceType(ManagedResource.ResourceType.URL)
                .build();
        ResourceNamingSuggestionResponse response = ResourceNamingSuggestionResponse.fromMap(
                Map.of("stats", Map.of("itemCount", 1)));
        when(aiNativeProcessor.process(ArgumentMatchers.<AIRequest<ResourceNamingContext>>any(), eq(ResourceNamingSuggestionResponse.class)))
                .thenReturn(Mono.just(response));

        service.processResourceBatch(List.of(resource));

        assertThat(resource.getFriendlyName()).isEqualTo("users Feature");
        assertThat(resource.getDescription()).isEqualTo("AI suggestion unavailable");
    }

    @Test
    @DisplayName("Partial LLM response applies matched resources and falls back missing resources only")
    void processResourceBatch_fallsBackOnlyMissingResources() {
        ManagedResource users = ManagedResource.builder()
                .resourceIdentifier("/contexa/admin/users")
                .resourceType(ManagedResource.ResourceType.URL)
                .build();
        ManagedResource groups = ManagedResource.builder()
                .resourceIdentifier("/contexa/admin/groups")
                .resourceType(ManagedResource.ResourceType.URL)
                .build();
        ResourceNamingSuggestionResponse response = new ResourceNamingSuggestionResponse(
                List.of(ResourceNamingSuggestionResponse.ResourceNamingSuggestion.builder()
                        .identifier("/contexa/admin/users")
                        .friendlyName("User Accounts")
                        .description("Manage user account records.")
                        .confidence(0.93)
                        .build()),
                List.of());
        when(aiNativeProcessor.process(ArgumentMatchers.<AIRequest<ResourceNamingContext>>any(), eq(ResourceNamingSuggestionResponse.class)))
                .thenReturn(Mono.just(response));

        service.processResourceBatch(List.of(users, groups));

        assertThat(users.getFriendlyName()).isEqualTo("User Accounts");
        assertThat(users.getDescription()).isEqualTo("Manage user account records.");
        assertThat(groups.getFriendlyName()).isEqualTo("groups Feature");
        assertThat(groups.getDescription()).isEqualTo("AI suggestion unavailable");
    }
}