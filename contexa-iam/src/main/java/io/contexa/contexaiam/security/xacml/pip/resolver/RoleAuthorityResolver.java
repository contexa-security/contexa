package io.contexa.contexaiam.security.xacml.pip.resolver;

import io.contexa.contexaiam.security.core.auth.PermissionAuthority;
import io.contexa.contexaiam.security.core.auth.RoleAuthority;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import java.util.HashSet;
import java.util.Set;

@RequiredArgsConstructor
public class RoleAuthorityResolver implements SubjectAuthorityResolver {
    private final RoleRepository roleRepository;

    @Override
    public boolean supports(String subjectType) {
        return "ROLE".equalsIgnoreCase(subjectType);
    }

    @Override
    public Set<GrantedAuthority> resolveAuthorities(Long subjectId) {
        Role role = roleRepository.findByIdWithPermissions(subjectId)
                .orElseThrow(() -> new IllegalArgumentException("Role not found with ID: " + subjectId));

        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new RoleAuthority(role));
        role.getRolePermissions().forEach(rp -> authorities.add(new PermissionAuthority(rp.getPermission())));

        return authorities;
    }
}
