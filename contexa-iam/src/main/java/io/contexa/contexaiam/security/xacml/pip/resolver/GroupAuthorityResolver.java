package io.contexa.contexaiam.security.xacml.pip.resolver;

import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.security.authority.RoleAuthority;
import io.contexa.contexacommon.security.authority.PermissionAuthority;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import java.util.*;

@RequiredArgsConstructor
public class GroupAuthorityResolver implements SubjectAuthorityResolver {
    private final GroupRepository groupRepository;

    @Override
    public boolean supports(String subjectType) {
        return "GROUP".equalsIgnoreCase(subjectType);
    }

    @Override
    public Set<GrantedAuthority> resolveAuthorities(Long subjectId) {
        Group group = groupRepository.findByIdWithRoles(subjectId)
                .orElseThrow(() -> new IllegalArgumentException("Group not found with ID: " + subjectId));

        Set<GrantedAuthority> authorities = new HashSet<>();

        Optional.ofNullable(group.getGroupRoles())
                .orElse(Collections.emptySet())
                .stream()
                .map(GroupRole::getRole)
                .filter(Objects::nonNull)
                .forEach(role -> {
                    authorities.add(new RoleAuthority(role));

                    Optional.ofNullable(role.getRolePermissions())
                            .orElse(Collections.emptySet())
                            .stream()
                            .map(RolePermission::getPermission)
                            .filter(Objects::nonNull)
                            .forEach(permission -> {
                                authorities.add(new PermissionAuthority(permission));
                            });
                });

        return authorities;
    }
}