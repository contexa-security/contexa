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

import io.contexa.contexaiam.domain.dto.*;
import io.contexa.contexaiam.repository.BusinessActionRepository;
import io.contexa.contexaiam.repository.BusinessResourceRepository;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexacommon.entity.business.BusinessAction;
import io.contexa.contexacommon.entity.business.BusinessResource;
import io.contexa.contexacommon.entity.business.BusinessResourceAction;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class BusinessMetadataServiceImpl implements BusinessMetadataService {

    private final BusinessResourceRepository businessResourceRepository;
    private final BusinessActionRepository businessActionRepository;
    private final ConditionTemplateRepository conditionTemplateRepository;
    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    private final RoleService roleService;
    private final ModelMapper modelMapper;

    @Override
    public List<BusinessResourceDto> getAllBusinessResources() {
        return businessResourceRepository.findAll().stream()
                .map(action -> modelMapper.map(action, BusinessResourceDto.class))
                .toList();
    }

    @Override
    public List<BusinessActionDto> getAllBusinessActions() {
        return businessActionRepository.findAll().stream()
                .map(action -> modelMapper.map(action, BusinessActionDto.class))
                .toList();
    }

    @Override
    public List<BusinessAction> getActionsForResource(Long businessResourceId) {
        if (businessResourceId == null) {
            return Collections.emptyList();
        }

        Optional<BusinessResource> resourceOptional = businessResourceRepository.findById(businessResourceId);

        return resourceOptional.map(businessResource -> businessResource.getAvailableActions().stream()
                .map(BusinessResourceAction::getBusinessAction)
                .collect(Collectors.toList())).orElseGet(Collections::emptyList);
    }

    @Override
    public List<ConditionTemplate> getAllConditionTemplates() {
        return conditionTemplateRepository.findAll();
    }

    @Override
    public List<UserMetadataDto> getAllUsersForPolicy() {
        return userRepository.findAll().stream()
                .map(user -> modelMapper.map(user, UserMetadataDto.class))
                .collect(Collectors.toList());
    }

    @Override
    public List<GroupMetadataDto> getAllGroupsForPolicy() {
        return groupRepository.findAll().stream()
                .map(group -> modelMapper.map(group, GroupMetadataDto.class))
                .collect(Collectors.toList());
    }

    @Override
    public Map<String, Object> getAllUsersAndGroups() {
        return Map.of(
                "users", getAllUsersForPolicy(),
                "groups", getAllGroupsForPolicy()
        );
    }

    @Override
    public List<RoleMetadataDto> getAllRoles() {
        return roleService.getRoles().stream()
                .map(role -> modelMapper.map(role, RoleMetadataDto.class))
                .collect(Collectors.toList());
    }

}
