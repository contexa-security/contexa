package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.repository.*;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.AccessCenterController;
import io.contexa.contexaiam.admin.web.center.service.AccessCenterService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
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
