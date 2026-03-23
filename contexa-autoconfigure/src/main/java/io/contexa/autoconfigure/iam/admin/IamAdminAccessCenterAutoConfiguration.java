package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.repository.*;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.AccessCenterController;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@AutoConfigureAfter(IamAdminAuthAutoConfiguration.class)
public class IamAdminAccessCenterAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AccessCenterController accessCenterController(
            UserRepository userRepository,
            UserRoleRepository userRoleRepository,
            GroupRepository groupRepository,
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            RoleService roleService) {
        return new AccessCenterController(
                userRepository, userRoleRepository, groupRepository,
                roleRepository, permissionRepository, roleService);
    }
}
