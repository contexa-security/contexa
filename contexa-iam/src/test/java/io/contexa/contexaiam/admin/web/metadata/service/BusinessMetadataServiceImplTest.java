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

import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.business.BusinessAction;
import io.contexa.contexacommon.entity.business.BusinessResource;
import io.contexa.contexacommon.entity.business.BusinessResourceAction;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.domain.dto.*;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.repository.BusinessActionRepository;
import io.contexa.contexaiam.repository.BusinessResourceRepository;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.modelmapper.ModelMapper;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("BusinessMetadataServiceImpl")
class BusinessMetadataServiceImplTest {

    @Mock private BusinessResourceRepository businessResourceRepository;
    @Mock private BusinessActionRepository businessActionRepository;
    @Mock private ConditionTemplateRepository conditionTemplateRepository;
    @Mock private UserRepository userRepository;
    @Mock private GroupRepository groupRepository;
    @Mock private RoleService roleService;
    @Mock private ModelMapper modelMapper;

    @InjectMocks
    private BusinessMetadataServiceImpl service;

    @Test
    @DisplayName("getAllBusinessResources should map entities to DTOs")
    void getAllBusinessResources() {
        BusinessResource res = new BusinessResource();
        when(businessResourceRepository.findAll()).thenReturn(List.of(res));
        when(modelMapper.map(res, BusinessResourceDto.class)).thenReturn(new BusinessResourceDto());

        List<BusinessResourceDto> result = service.getAllBusinessResources();

        assertThat(result).hasSize(1);
        verify(businessResourceRepository).findAll();
    }

    @Test
    @DisplayName("getAllBusinessActions should map entities to DTOs")
    void getAllBusinessActions() {
        BusinessAction act = new BusinessAction();
        when(businessActionRepository.findAll()).thenReturn(List.of(act));
        when(modelMapper.map(act, BusinessActionDto.class)).thenReturn(new BusinessActionDto());

        List<BusinessActionDto> result = service.getAllBusinessActions();

        assertThat(result).hasSize(1);
        verify(businessActionRepository).findAll();
    }

    @Nested
    @DisplayName("getActionsForResource")
    class GetActions {

        @Test
        @DisplayName("should return empty list when resourceId is null")
        void nullId() {
            List<BusinessAction> result = service.getActionsForResource(null);
            assertThat(result).isEmpty();
            verifyNoInteractions(businessResourceRepository);
        }

        @Test
        @DisplayName("should return empty list when resource is not found")
        void notFound() {
            when(businessResourceRepository.findById(99L)).thenReturn(Optional.empty());

            List<BusinessAction> result = service.getActionsForResource(99L);
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("should return action list when resource is found")
        void success() {
            BusinessResource resource = new BusinessResource();
            BusinessAction action = new BusinessAction();
            BusinessResourceAction bra = new BusinessResourceAction(
                    new BusinessResourceAction.BusinessResourceActionId(1L, 2L),
                    resource,
                    action,
                    "PERM"
            );
            resource.setAvailableActions(Set.of(bra));

            when(businessResourceRepository.findById(1L)).thenReturn(Optional.of(resource));

            List<BusinessAction> result = service.getActionsForResource(1L);

            assertThat(result).containsExactly(action);
        }
    }

    @Test
    @DisplayName("getAllConditionTemplates should delegate to repository")
    void getAllConditionTemplates() {
        ConditionTemplate ct = new ConditionTemplate();
        when(conditionTemplateRepository.findAll()).thenReturn(List.of(ct));

        List<ConditionTemplate> result = service.getAllConditionTemplates();

        assertThat(result).containsExactly(ct);
    }

    @Test
    @DisplayName("getAllUsersForPolicy should map to UserMetadataDto")
    void getAllUsersForPolicy() {
        Users user = new Users();
        when(userRepository.findAll()).thenReturn(List.of(user));
        when(modelMapper.map(user, UserMetadataDto.class)).thenReturn(new UserMetadataDto());

        List<UserMetadataDto> result = service.getAllUsersForPolicy();

        assertThat(result).hasSize(1);
    }

    @Test
    @DisplayName("getAllGroupsForPolicy should map to GroupMetadataDto")
    void getAllGroupsForPolicy() {
        Group group = new Group();
        when(groupRepository.findAll()).thenReturn(List.of(group));
        when(modelMapper.map(group, GroupMetadataDto.class)).thenReturn(new GroupMetadataDto());

        List<GroupMetadataDto> result = service.getAllGroupsForPolicy();

        assertThat(result).hasSize(1);
    }

    @Test
    @DisplayName("getAllUsersAndGroups should aggregate user and group lists")
    void getAllUsersAndGroups() {
        Users user = new Users();
        Group group = new Group();
        when(userRepository.findAll()).thenReturn(List.of(user));
        when(groupRepository.findAll()).thenReturn(List.of(group));
        when(modelMapper.map(user, UserMetadataDto.class)).thenReturn(new UserMetadataDto());
        when(modelMapper.map(group, GroupMetadataDto.class)).thenReturn(new GroupMetadataDto());

        Map<String, Object> result = service.getAllUsersAndGroups();

        assertThat(result).containsKeys("users", "groups");
        assertThat((List<?>) result.get("users")).hasSize(1);
        assertThat((List<?>) result.get("groups")).hasSize(1);
    }

    @Test
    @DisplayName("getAllRoles should map roles to RoleMetadataDto")
    void getAllRoles() {
        Role role = new Role();
        when(roleService.getRoles()).thenReturn(List.of(role));
        when(modelMapper.map(role, RoleMetadataDto.class)).thenReturn(new RoleMetadataDto());

        List<RoleMetadataDto> result = service.getAllRoles();

        assertThat(result).hasSize(1);
    }
}
