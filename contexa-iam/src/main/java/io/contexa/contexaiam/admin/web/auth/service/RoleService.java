package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.entity.Role;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface RoleService {
    Role getRole(long id);
    List<Role> getRoles();
    List<Role> getRolesWithoutExpression();
    Page<Role> searchRoles(String keyword, Pageable pageable);
    Role createRole(Role role, List<Long> permissionIds);
    Role updateRole(Role role, List<Long> permissionIds);
    void deleteRole(long id);
}
