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
package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.GroupRole;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.RolePermission;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.admin.web.monitoring.dto.MatrixFilter;
import io.contexa.contexaiam.admin.web.monitoring.dto.PermissionMatrixDto;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("PermissionMatrixServiceImpl")
class PermissionMatrixServiceImplTest {

    @Mock private GroupRepository groupRepository;
    @Mock private PermissionCatalogService permissionCatalogService;

    @InjectMocks
    private PermissionMatrixServiceImpl service;

    @Test
    @DisplayName("getPermissionMatrix without filter should return full matrix")
    void getPermissionMatrixNoFilter() {
        Group group = Group.builder().id(10L).name("GroupA").build();
        Role role = Role.builder().id(100L).build();
        Permission permission = Permission.builder().id(1000L).friendlyName("Read").build();
        role.setRolePermissions(Set.of(RolePermission.builder().role(role).permission(permission).build()));
        GroupRole gr = GroupRole.builder().group(group).role(role).build();
        group.setGroupRoles(Set.of(gr));

        when(groupRepository.findAllWithRolesAndPermissions()).thenReturn(List.of(group));

        PermissionDto dto = PermissionDto.builder().id(1000L).friendlyName("Read").build();
        when(permissionCatalogService.getAvailablePermissions()).thenReturn(List.of(dto));

        PermissionMatrixDto matrix = service.getPermissionMatrix();

        assertThat(matrix.subjects()).containsExactly("GroupA");
        assertThat(matrix.permissions()).containsExactly("Read");
        assertThat(matrix.matrixData().get("GroupA").get("Read")).isEqualTo("GRANT");
    }

    @Test
    @DisplayName("getPermissionMatrix with filter should query by subject ids")
    void getPermissionMatrixWithFilter() {
        Group group = Group.builder().id(10L).name("GroupA").build();
        group.setGroupRoles(Set.of());

        when(groupRepository.findAllById(Set.of(10L))).thenReturn(List.of(group));

        PermissionDto dto = PermissionDto.builder().id(1000L).friendlyName("Read").build();
        when(permissionCatalogService.getAvailablePermissions()).thenReturn(List.of(dto));

        MatrixFilter filter = new MatrixFilter(Set.of(10L), null, null);
        PermissionMatrixDto matrix = service.getPermissionMatrix(filter);

        assertThat(matrix.subjects()).containsExactly("GroupA");
        assertThat(matrix.matrixData().get("GroupA").get("Read")).isEqualTo("NONE");
    }
}
