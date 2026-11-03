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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.metadata.controller.ResourceAdminController;
import io.contexa.contexaiam.admin.web.metadata.service.BusinessMetadataService;
import io.contexa.contexaiam.admin.web.metadata.service.BusinessMetadataServiceImpl;
import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogServiceImpl;
import io.contexa.contexaiam.admin.web.metadata.service.ResourceAdminService;
import io.contexa.contexaiam.repository.BusinessActionRepository;
import io.contexa.contexaiam.repository.BusinessResourceRepository;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.FunctionCatalogRepository;
import io.contexa.contexaiam.repository.FunctionGroupRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import org.modelmapper.ModelMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.beans.factory.annotation.Qualifier;

@AutoConfiguration
public class IamAdminMetadataAutoConfiguration {

    @Bean(name = "contexaResourceAdminService")
    @ConditionalOnMissingBean
    public ResourceAdminService resourceAdminService(
            ResourceRegistryService contexaResourceRegistryService,
            ManagedResourceRepository managedResourceRepository,
            MessageSource messageSource) {
        return new ResourceAdminService(contexaResourceRegistryService, managedResourceRepository, messageSource);
    }

    @Bean(name = "contexaResourceAdminController")
    @ConditionalOnMissingBean
    public ResourceAdminController resourceAdminController(ResourceAdminService contexaResourceAdminService) {
        return new ResourceAdminController(contexaResourceAdminService);
    }

    @Bean(name = "contexaFunctionCatalogService")
    @ConditionalOnMissingBean
    public FunctionCatalogService functionCatalogService(
            FunctionCatalogRepository functionCatalogRepository,
            FunctionGroupRepository functionGroupRepository,
            @Qualifier("contexaModelMapper") ModelMapper contexaModelMapper) {
        return new FunctionCatalogService(
                functionCatalogRepository, functionGroupRepository, contexaModelMapper);
    }

    @Bean(name = "contexaPermissionCatalogService")
    @ConditionalOnMissingBean
    public PermissionCatalogService permissionCatalogService(
            PermissionRepository permissionRepository,
            @Qualifier("contexaModelMapper") ModelMapper contexaModelMapper,
            PolicyService contexaPolicyService,
            MessageSource messageSource) {
        return new PermissionCatalogServiceImpl(permissionRepository, contexaModelMapper, contexaPolicyService, messageSource);
    }

    @Bean(name = "contexaBusinessMetadataService")
    @ConditionalOnMissingBean
    public BusinessMetadataService businessMetadataService(
            BusinessResourceRepository businessResourceRepository,
            BusinessActionRepository businessActionRepository,
            ConditionTemplateRepository conditionTemplateRepository,
            UserRepository userRepository,
            GroupRepository groupRepository,
            RoleService contexaRoleService,
            @Qualifier("contexaModelMapper") ModelMapper contexaModelMapper) {
        return new BusinessMetadataServiceImpl(
                businessResourceRepository, businessActionRepository, conditionTemplateRepository,
                userRepository, groupRepository, contexaRoleService, contexaModelMapper);
    }
}

