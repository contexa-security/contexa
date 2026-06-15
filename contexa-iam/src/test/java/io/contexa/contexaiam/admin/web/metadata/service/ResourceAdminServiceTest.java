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
package io.contexa.contexaiam.admin.web.metadata.service;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.*;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ResourceAdminService")
class ResourceAdminServiceTest {

    @Mock private ResourceRegistryService resourceRegistryService;
    @Mock private ManagedResourceRepository managedResourceRepository;
    @Mock private MessageSource messageSource;

    @InjectMocks
    private ResourceAdminService service;

    @BeforeEach
    void setUp() {
        lenient().when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    @DisplayName("getWorkbenchPage should build model with sorted items")
    void getWorkbenchPage() {
        ResourceSearchForm form = new ResourceSearchForm();
        form.setKeyword("k");
        form.setResourceType("URL");
        form.setStatus("NEEDS_DEFINITION");

        ManagedResource mr = ManagedResource.builder()
                .id(1L)
                .resourceIdentifier("/api")
                .resourceType(ManagedResource.ResourceType.URL)
                .status(ManagedResource.Status.NEEDS_DEFINITION)
                .build();

        when(resourceRegistryService.findResources(any(), any())).thenReturn(new PageImpl<>(List.of(mr)));
        when(resourceRegistryService.getAllServiceOwners()).thenReturn(Set.of("IAM"));

        ResourceWorkbenchPageModel model = service.getWorkbenchPage(form, PageRequest.of(0, 10));

        assertThat(model.resourcePage().getContent()).hasSize(1);
        assertThat(model.resourcePage().getContent().get(0).resourceIdentifier()).isEqualTo("/api");
        assertThat(model.serviceOwners()).contains("IAM");
        assertThat(model.criteria().getKeyword()).isEqualTo("k");
    }

    @Test
    @DisplayName("refreshResources should delegate to registry")
    void refreshResources() {
        service.refreshResources();
        verify(resourceRegistryService).refreshAndSynchronizeResources();
    }

    @Test
    @DisplayName("defineResourceAsPermission should create permission and return response")
    void defineResourceAsPermission() {
        ResourceMetadataForm form = new ResourceMetadataForm();
        form.setFriendlyName("FN");

        Permission perm = Permission.builder().id(100L).friendlyName("FN").build();
        when(resourceRegistryService.defineResourceAsPermission(eq(1L), any())).thenReturn(perm);

        ResourceDefineResponse res = service.defineResourceAsPermission(1L, form);

        assertThat(res.message()).isEqualTo("msg.resource.permission.created");
        assertThat(res.permissionId()).isEqualTo(100L);
    }

    @Nested
    @DisplayName("defineResourcesBatch")
    class Batch {

        @Test
        @DisplayName("should handle missing id, duplicate skip, success and error flows")
        void success() {
            // Req 1: missing resource ID
            ResourceBatchDefineRequest req1 = new ResourceBatchDefineRequest(null, "FN1", "D1");

            // Req 2: skipped (already defined)
            ResourceBatchDefineRequest req2 = new ResourceBatchDefineRequest(2L, "FN2", "D2");
            Permission p2 = Permission.builder().id(200L).friendlyName("P2").build();
            ManagedResource r2 = ManagedResource.builder().id(2L).permission(p2).build();
            when(managedResourceRepository.findById(2L)).thenReturn(Optional.of(r2));

            // Req 3: created successfully
            ResourceBatchDefineRequest req3 = new ResourceBatchDefineRequest(3L, "FN3", "D3");
            ManagedResource r3 = ManagedResource.builder().id(3L).build();
            Permission p3 = Permission.builder().id(300L).friendlyName("FN3").build();
            when(managedResourceRepository.findById(3L)).thenReturn(Optional.of(r3));
            when(resourceRegistryService.defineResourceAsPermission(eq(3L), any())).thenReturn(p3);

            // Req 4: error during creation
            ResourceBatchDefineRequest req4 = new ResourceBatchDefineRequest(4L, "FN4", "D4");
            when(managedResourceRepository.findById(4L)).thenReturn(Optional.empty());
            when(resourceRegistryService.defineResourceAsPermission(eq(4L), any()))
                    .thenThrow(new RuntimeException("create failed"));

            List<ResourceBatchDefineResult> res = service.defineResourcesBatch(List.of(req1, req2, req3, req4));

            assertThat(res).hasSize(4);
            assertThat(res.get(0).error()).isEqualTo("resourceId is required");
            assertThat(res.get(1).skipped()).isTrue();
            assertThat(res.get(2).skipped()).isFalse();
            assertThat(res.get(2).permissionId()).isEqualTo(300L);
            assertThat(res.get(3).error()).contains("create failed");
        }
    }

    @Test
    @DisplayName("restoreResource should set status to NEEDS_DEFINITION")
    void restoreResource() {
        ResourceStatusResponse res = service.restoreResource(1L);

        assertThat(res.resourceId()).isEqualTo(1L);
        assertThat(res.newStatus()).isEqualTo("NEEDS_DEFINITION");
        verify(resourceRegistryService).updateResourceManagementStatus(eq(1L), any());
    }

    @Test
    @DisplayName("excludeResource should exclude resource")
    void excludeResource() {
        ResourceStatusResponse res = service.excludeResource(1L);

        assertThat(res.resourceId()).isEqualTo(1L);
        assertThat(res.newStatus()).isEqualTo("EXCLUDED");
        verify(resourceRegistryService).excludeResourceFromManagement(1L);
    }

    @Test
    @DisplayName("updateManagementStatus should delegate to registry")
    void updateManagementStatus() {
        ResourceManagementForm form = new ResourceManagementForm();
        form.setStatus("EXCLUDED");

        service.updateManagementStatus(1L, form);

        verify(resourceRegistryService).updateResourceManagementStatus(eq(1L), any());
    }
}
