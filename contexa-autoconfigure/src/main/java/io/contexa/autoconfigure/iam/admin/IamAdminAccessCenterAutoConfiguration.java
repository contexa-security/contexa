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

import io.contexa.contexacommon.repository.*;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.AccessCenterController;
import io.contexa.contexaiam.admin.web.center.service.AccessCenterService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@AutoConfigureAfter(IamAdminAuthAutoConfiguration.class)
public class IamAdminAccessCenterAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AccessCenterService accessCenterService(
            UserRepository userRepository,
            UserRoleRepository userRoleRepository,
            GroupRepository groupRepository,
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            RoleService roleService,
            UserRolePermissionRepository userRolePermissionRepository,
            GroupRolePermissionRepository groupRolePermissionRepository) {
        return new AccessCenterService(
                userRepository, userRoleRepository, groupRepository,
                roleRepository, permissionRepository, roleService,
                userRolePermissionRepository, groupRolePermissionRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public AccessCenterController accessCenterController(AccessCenterService accessCenterService) {
        return new AccessCenterController(accessCenterService);
    }
}

