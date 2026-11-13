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
import io.contexa.contexacore.exception.StrategicOperationConflictException;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingSuggestionResponse;
import io.contexa.contexaiam.properties.IamAdminProperties;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.resource.scanner.ResourceScanner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.springframework.context.support.StaticMessageSource;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
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

    @Test
    @DisplayName("A request refused for an identical running one is neither named by default nor saved")
    void processResourceBatch_doesNotFallBackWhenAnIdenticalRequestIsRunning() {
        ManagedResource resource = ManagedResource.builder()
                .resourceIdentifier("/contexa/admin/users")
                .resourceType(ManagedResource.ResourceType.URL)
                .friendlyName("listUsers")
                .description("scanner description")
                .build();
        when(aiNativeProcessor.process(ArgumentMatchers.<AIRequest<ResourceNamingContext>>any(), eq(ResourceNamingSuggestionResponse.class)))
                .thenReturn(Mono.error(new StrategicOperationConflictException("Strategic operation conflict: strategy-x")));

        assertThatThrownBy(() -> service.processResourceBatch(List.of(resource)))
                .isInstanceOf(StrategicOperationConflictException.class);

        assertThat(resource.getFriendlyName()).isEqualTo("listUsers");
        assertThat(resource.getDescription()).isEqualTo("scanner description");
        verify(managedResourceRepository, never()).saveAll(any());
    }

    @Test
    @DisplayName("Any other failure still saves the resources with defaults")
    void processResourceBatch_stillFallsBackWhenTheModelFails() {
        ManagedResource resource = ManagedResource.builder()
                .resourceIdentifier("/contexa/admin/users")
                .resourceType(ManagedResource.ResourceType.URL)
                .build();
        when(aiNativeProcessor.process(ArgumentMatchers.<AIRequest<ResourceNamingContext>>any(), eq(ResourceNamingSuggestionResponse.class)))
                .thenReturn(Mono.error(new IllegalStateException("model unavailable")));

        service.processResourceBatch(List.of(resource));

        assertThat(resource.getDescription()).isEqualTo("AI suggestion unavailable");
        verify(managedResourceRepository).saveAll(List.of(resource));
    }

    /**
     * IAM-D20: a refresh registers the discovered resources at once, under their scanner names, and does not wait for
     * the model. The naming runs after the refresh, and names the resources still awaiting definition.
     */
    @Test
    @DisplayName("A refresh registers new resources at once and names them in the background")
    @SuppressWarnings("unchecked")
    void refreshRegistersAtOnceAndNamesInTheBackground() {
        List<Runnable> scheduled = new ArrayList<>();
        ManagedResource discovered = ManagedResource.builder()
                .resourceIdentifier("/contexa/admin/users")
                .resourceType(ManagedResource.ResourceType.URL)
                .friendlyName("listUsers")
                .description("URL: [GET] /contexa/admin/users")
                .build();
        ResourceScanner scanner = () -> List.of(discovered);
        ResourceRegistryServiceImpl refreshing = new ResourceRegistryServiceImpl(List.of(scanner),
                managedResourceRepository, mock(PermissionCatalogService.class), aiNativeProcessor,
                mock(AutoConditionTemplateService.class), mock(PolicyRepository.class), new IamAdminProperties(),
                new StaticMessageSource(), scheduled::add);
        when(managedResourceRepository.saveAll(anyList())).thenAnswer(invocation -> {
            List<ManagedResource> saved = invocation.getArgument(0);
            saved.forEach(resource -> resource.setId(7L));
            return saved;
        });

        refreshing.refreshAndSynchronizeResources();

        verify(managedResourceRepository).saveAll(List.of(discovered));
        verify(aiNativeProcessor, never()).process(any(), any());
        assertThat(scheduled).hasSize(1);

        ManagedResource stored = copyOf(discovered);
        when(managedResourceRepository.findAllById(List.of(7L))).thenReturn(List.of(stored), List.of(copyOf(stored)));
        when(aiNativeProcessor.process(ArgumentMatchers.<AIRequest<ResourceNamingContext>>any(), eq(ResourceNamingSuggestionResponse.class)))
                .thenReturn(Mono.just(suggestion("/contexa/admin/users", "User Accounts")));
        ArgumentCaptor<List<ManagedResource>> named = ArgumentCaptor.forClass(List.class);

        scheduled.get(0).run();

        verify(managedResourceRepository, times(2)).saveAll(named.capture());
        assertThat(named.getValue()).singleElement()
                .extracting(ManagedResource::getFriendlyName).isEqualTo("User Accounts");
    }

    /** IAM-D20: a resource an administrator defined while the model was answering keeps the administrator's values. */
    @Test
    @DisplayName("A resource changed while the model answers keeps its current values")
    @SuppressWarnings("unchecked")
    void aResourceChangedWhileTheModelAnswersIsNotOverwritten() {
        ManagedResource read = ManagedResource.builder()
                .id(9L)
                .resourceIdentifier("/contexa/admin/groups")
                .resourceType(ManagedResource.ResourceType.URL)
                .friendlyName("listGroups")
                .description("URL: [GET] /contexa/admin/groups")
                .build();
        ManagedResource defined = copyOf(read);
        defined.setFriendlyName("Group directory");
        defined.setStatus(ManagedResource.Status.PERMISSION_CREATED);
        when(managedResourceRepository.findAllById(List.of(9L))).thenReturn(List.of(read), List.of(defined));
        when(aiNativeProcessor.process(ArgumentMatchers.<AIRequest<ResourceNamingContext>>any(), eq(ResourceNamingSuggestionResponse.class)))
                .thenReturn(Mono.just(suggestion("/contexa/admin/groups", "Groups")));
        ArgumentCaptor<List<ManagedResource>> saved = ArgumentCaptor.forClass(List.class);

        service.nameRegisteredResources(List.of(9L));

        verify(managedResourceRepository).saveAll(saved.capture());
        assertThat(saved.getValue()).isEmpty();
        assertThat(defined.getFriendlyName()).isEqualTo("Group directory");
    }

    private static ManagedResource copyOf(ManagedResource source) {
        return ManagedResource.builder()
                .id(source.getId() == null ? 7L : source.getId())
                .resourceIdentifier(source.getResourceIdentifier())
                .resourceType(source.getResourceType())
                .friendlyName(source.getFriendlyName())
                .description(source.getDescription())
                .status(source.getStatus())
                .build();
    }

    private static ResourceNamingSuggestionResponse suggestion(String identifier, String friendlyName) {
        return new ResourceNamingSuggestionResponse(
                List.of(ResourceNamingSuggestionResponse.ResourceNamingSuggestion.builder()
                        .identifier(identifier)
                        .friendlyName(friendlyName)
                        .description(friendlyName + " records.")
                        .confidence(0.9)
                        .build()),
                List.of());
    }

}