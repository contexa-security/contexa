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
package io.contexa.contexaiam.admin.web.metadata.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceManagementForm;
import io.contexa.contexaiam.admin.web.metadata.service.ResourceAdminService;
import io.contexa.contexaiam.domain.dto.ResourceManagementDto;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.quality.Strictness;
import org.springframework.context.MessageSource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("ResourceAdminController contract")
class ResourceAdminControllerTest {

    @Mock
    private ResourceRegistryService resourceRegistryService;

    @Mock
    private ManagedResourceRepository managedResourceRepository;

    @Mock
    private MessageSource messageSource;

    private ResourceAdminController controller;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        when(messageSource.getMessage(any(), any(), any(Locale.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        ResourceAdminService resourceAdminService =
                new ResourceAdminService(resourceRegistryService, managedResourceRepository, messageSource);
        controller = new ResourceAdminController(resourceAdminService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setCustomArgumentResolvers(new PageableHandlerMethodArgumentResolver())
                .build();
    }

    @Nested
    @DisplayName("page")
    class PageWorkbench {

        @Test
        @DisplayName("keeps existing view and model names")
        void resourceWorkbenchPage() throws Exception {
            ManagedResource resource = ManagedResource.builder()
                    .id(1L)
                    .resourceIdentifier("/api/orders")
                    .resourceType(ManagedResource.ResourceType.URL)
                    .friendlyName("Orders")
                    .status(ManagedResource.Status.NEEDS_DEFINITION)
                    .build();
            when(resourceRegistryService.findResources(any(), any()))
                    .thenReturn(new PageImpl<>(List.of(resource), PageRequest.of(0, 10), 1));
            when(resourceRegistryService.getAllServiceOwners()).thenReturn(Set.of("billing"));

            MvcResult result = mockMvc.perform(get("/admin/workbench/resources"))
                    .andExpect(status().isOk())
                    .andExpect(view().name("admin/resource-workbench"))
                    .andExpect(model().attribute("activePage", "policy-center"))
                    .andReturn();

            assertThat(result.getModelAndView().getModel()).containsKeys("resourcePage", "serviceOwners", "criteria");
            assertThat(result.getModelAndView().getModel().get("serviceOwners")).isEqualTo(Set.of("billing"));
            assertThat(result.getModelAndView().getModel().get("criteria")).isNotNull();

            Page<?> resourcePage =
                    (Page<?>) result.getModelAndView().getModel().get("resourcePage");
            Object resourceView = resourcePage.getContent().get(0);
            Object resourceType = resourceView.getClass().getMethod("getResourceType").invoke(resourceView);
            Object status = resourceView.getClass().getMethod("getStatus").invoke(resourceView);
            assertThat(resourceType.getClass().getName())
                    .startsWith("io.contexa.contexaiam.admin.web.metadata.dto");
            assertThat(status.getClass().getName())
                    .startsWith("io.contexa.contexaiam.admin.web.metadata.dto");
            assertThat(resourceType.toString()).isEqualTo("URL");
            assertThat(resourceType.getClass().getMethod("name").invoke(resourceType)).isEqualTo("URL");
            assertThat(status.toString()).isEqualTo("NEEDS_DEFINITION");
            assertThat(status.getClass().getMethod("name").invoke(status)).isEqualTo("NEEDS_DEFINITION");
        }
    }

    @Nested
    @DisplayName("define")
    class Define {

        @Test
        @DisplayName("single define keeps form request and response JSON")
        void defineResourceAsPermissionApi() throws Exception {
            Permission permission = Permission.builder().id(100L).friendlyName("Orders Read").build();
            when(resourceRegistryService.defineResourceAsPermission(any(), any())).thenReturn(permission);

            mockMvc.perform(post("/admin/workbench/resources/1/define")
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .param("friendlyName", "Orders Read")
                            .param("description", "Read orders"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("msg.resource.permission.created"))
                    .andExpect(jsonPath("$.permissionId").value(100))
                    .andExpect(jsonPath("$.permissionName").value("Orders Read"));
        }

        @Test
        @DisplayName("single define error keeps bad request message JSON")
        void defineResourceAsPermissionApiError() throws Exception {
            when(resourceRegistryService.defineResourceAsPermission(any(), any()))
                    .thenThrow(new RuntimeException("definition failed"));

            mockMvc.perform(post("/admin/workbench/resources/1/define")
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .param("friendlyName", "Orders Read"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message").value("definition failed"));
        }

        @Test
        @DisplayName("batch define keeps mixed result JSON")
        void defineResourcesBatch() throws Exception {
            Permission existingPermission = Permission.builder().id(100L).friendlyName("Existing").build();
            ManagedResource existingResource = ManagedResource.builder()
                    .id(1L)
                    .permission(existingPermission)
                    .build();
            Permission newPermission = Permission.builder().id(200L).friendlyName("New Permission").build();
            when(managedResourceRepository.findById(1L)).thenReturn(Optional.of(existingResource));
            when(managedResourceRepository.findById(2L)).thenReturn(Optional.empty());
            when(managedResourceRepository.findById(3L)).thenReturn(Optional.empty());
            when(resourceRegistryService.defineResourceAsPermission(Mockito.eq(2L), any()))
                    .thenReturn(newPermission);
            when(resourceRegistryService.defineResourceAsPermission(Mockito.eq(3L), any()))
                    .thenThrow(new RuntimeException("create failed"));

            mockMvc.perform(post("/admin/workbench/resources/define-batch")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    [
                                      {"resourceId":1,"friendlyName":"Ignored","description":"Ignored"},
                                      {"resourceId":2,"friendlyName":"New Permission","description":"New desc"},
                                      {"resourceId":3,"friendlyName":"Fail","description":"Fail desc"},
                                      {"friendlyName":"Missing"}
                                    ]
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].resourceId").value(1))
                    .andExpect(jsonPath("$[0].permissionId").value(100))
                    .andExpect(jsonPath("$[0].permissionName").value("Existing"))
                    .andExpect(jsonPath("$[0].skipped").value(true))
                    .andExpect(jsonPath("$[1].resourceId").value(2))
                    .andExpect(jsonPath("$[1].permissionId").value(200))
                    .andExpect(jsonPath("$[1].permissionName").value("New Permission"))
                    .andExpect(jsonPath("$[1].skipped").value(false))
                    .andExpect(jsonPath("$[2].resourceId").value(3))
                    .andExpect(jsonPath("$[2].error").value("create failed"))
                    .andExpect(jsonPath("$[2].skipped").value(true))
                    .andExpect(jsonPath("$[3].error").value("resourceId is required"))
                    .andExpect(jsonPath("$[3].skipped").value(true));
        }

        @Test
        @DisplayName("batch define accepts numeric string ids without server error")
        void defineResourcesBatchNumericStringId() throws Exception {
            Permission newPermission = Permission.builder().id(200L).friendlyName("New Permission").build();
            when(managedResourceRepository.findById(2L)).thenReturn(Optional.empty());
            when(resourceRegistryService.defineResourceAsPermission(Mockito.eq(2L), any()))
                    .thenReturn(newPermission);

            mockMvc.perform(post("/admin/workbench/resources/define-batch")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    [
                                      {"resourceId":"2","friendlyName":"New Permission","description":"New desc"}
                                    ]
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].resourceId").value(2))
                    .andExpect(jsonPath("$[0].permissionId").value(200))
                    .andExpect(jsonPath("$[0].skipped").value(false));
        }

        @Test
        @DisplayName("batch define rejects null request body without server error")
        void defineResourcesBatchNullBody() throws Exception {
            mockMvc.perform(post("/admin/workbench/resources/define-batch")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("null"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$[0].error").value("request body is required"))
                    .andExpect(jsonPath("$[0].skipped").value(true));
        }
    }

    @Nested
    @DisplayName("status")
    class Status {

        @Test
        @DisplayName("restore keeps response JSON")
        void restoreResource() throws Exception {
            mockMvc.perform(post("/admin/workbench/resources/1/restore"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Resource restored to management"))
                    .andExpect(jsonPath("$.resourceId").value(1))
                    .andExpect(jsonPath("$.newStatus").value("NEEDS_DEFINITION"));

            ArgumentCaptor<ResourceManagementDto> captor = ArgumentCaptor.forClass(ResourceManagementDto.class);
            verify(resourceRegistryService).updateResourceManagementStatus(Mockito.eq(1L), captor.capture());
            assertThat(captor.getValue().getStatus()).isEqualTo(ManagedResource.Status.NEEDS_DEFINITION);
        }

        @Test
        @DisplayName("exclude keeps response JSON")
        void excludeResource() throws Exception {
            mockMvc.perform(post("/admin/workbench/resources/1/exclude"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Resource excluded from management"))
                    .andExpect(jsonPath("$.resourceId").value(1))
                    .andExpect(jsonPath("$.newStatus").value("EXCLUDED"));

            verify(resourceRegistryService).excludeResourceFromManagement(1L);
        }

        @Test
        @DisplayName("manage redirect keeps flash message contract")
        void updateManagementStatus() {
            ResourceManagementForm dto = new ResourceManagementForm();
            dto.setStatus("POLICY_CONNECTED");
            RedirectAttributesModelMap redirectAttributes = new RedirectAttributesModelMap();

            String viewName = controller.updateManagementStatus(1L, dto, redirectAttributes);

            assertThat(viewName).isEqualTo("redirect:/admin/workbench/resources");
            assertThat(redirectAttributes.getFlashAttributes()).containsKey("message");
        }

        @Test
        @DisplayName("refresh redirect keeps error flash contract")
        void refreshResourcesError() {
            RedirectAttributesModelMap redirectAttributes = new RedirectAttributesModelMap();
            doThrow(new RuntimeException("refresh failed"))
                    .when(resourceRegistryService).refreshAndSynchronizeResources();

            String viewName = controller.refreshResources(redirectAttributes);

            assertThat(viewName).isEqualTo("redirect:/admin/workbench/resources");
            assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
        }
    }
}
