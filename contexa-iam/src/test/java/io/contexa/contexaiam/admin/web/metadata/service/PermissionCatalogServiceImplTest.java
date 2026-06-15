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
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("PermissionCatalogServiceImpl")
class PermissionCatalogServiceImplTest {

    @Mock private PermissionRepository permissionRepository;
    @Mock private ModelMapper modelMapper;
    @Mock private PolicyService policyService;
    @Mock private MessageSource messageSource;

    @InjectMocks
    private PermissionCatalogServiceImpl service;

    @BeforeEach
    void setUp() {
        lenient().when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    @Nested
    @DisplayName("synchronizePermissionFor")
    class Sync {

        @Test
        @DisplayName("should throw IllegalStateException when status is NEEDS_DEFINITION")
        void needsDefinition() {
            ManagedResource resource = ManagedResource.builder()
                    .id(1L)
                    .status(ManagedResource.Status.NEEDS_DEFINITION)
                    .build();

            assertThrows(IllegalStateException.class, () -> service.synchronizePermissionFor(resource));
        }

        @Test
        @DisplayName("should save permission and generate correct name for URL type")
        void successUrl() {
            ManagedResource resource = ManagedResource.builder()
                    .id(1L)
                    .status(ManagedResource.Status.PERMISSION_CREATED)
                    .resourceType(ManagedResource.ResourceType.URL)
                    .resourceIdentifier("/api/users/{id}/details")
                    .httpMethod(ManagedResource.HttpMethod.POST)
                    .friendlyName("Friendly")
                    .description("Desc")
                    .build();

            when(permissionRepository.findByName("URL_API_USERS_ID_DETAILS")).thenReturn(Optional.empty());
            when(permissionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            Permission result = service.synchronizePermissionFor(resource);

            assertThat(result.getName()).isEqualTo("URL_API_USERS_ID_DETAILS");
            assertThat(result.getActionType()).isEqualTo("POST");
            assertThat(result.getFriendlyName()).isEqualTo("Friendly");
            assertThat(result.getDescription()).isEqualTo("Desc");
            assertThat(result.isAutoCreated()).isTrue();
        }

        @Test
        @DisplayName("should generate correct name for METHOD type")
        void successMethod() {
            ManagedResource resource = ManagedResource.builder()
                    .id(1L)
                    .status(ManagedResource.Status.PERMISSION_CREATED)
                    .resourceType(ManagedResource.ResourceType.METHOD)
                    .resourceIdentifier("io.contexa.UserService.getUser(long)")
                    .friendlyName("Friendly")
                    .build();

            when(permissionRepository.findByName("METHOD_USERSERVICE_GETUSER")).thenReturn(Optional.empty());
            when(permissionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            Permission result = service.synchronizePermissionFor(resource);

            assertThat(result.getName()).isEqualTo("METHOD_USERSERVICE_GETUSER");
            assertThat(result.getActionType()).isEqualTo("EXECUTE");
        }
    }

    @Test
    @DisplayName("getAvailablePermissions should return mapped defined permissions")
    void getAvailablePermissions() {
        Permission p = new Permission();
        when(permissionRepository.findDefinedPermissionsWithDetails()).thenReturn(List.of(p));
        when(modelMapper.map(p, PermissionDto.class)).thenReturn(new PermissionDto());

        List<PermissionDto> result = service.getAvailablePermissions();

        assertThat(result).hasSize(1);
    }

    @Test
    @DisplayName("searchAvailablePermissions should return mapped paged permissions")
    void searchAvailablePermissions() {
        Permission p = new Permission();
        when(permissionRepository.searchAvailablePermissions(any(), any(), any()))
                .thenReturn(new PageImpl<>(List.of(p)));
        when(modelMapper.map(p, PermissionDto.class)).thenReturn(new PermissionDto());

        Page<PermissionDto> result = service.searchAvailablePermissions("keyword", List.of(1L), PageRequest.of(0, 10));

        assertThat(result.getContent()).hasSize(1);
    }
}
