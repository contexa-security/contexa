package io.contexa.contexaiam.security.xacml.pip.resolver;

import io.contexa.contexaiam.security.core.CustomUserDetails;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.GroupRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import java.util.HashSet;
import java.util.Set;

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
        // 가상의 사용자를 만들어 그룹 권한만 계산
        Users virtualUser = Users.builder().userGroups(Set.of(new UserGroup(null, group))).build();
        return new HashSet<>(new CustomUserDetails(virtualUser).getAuthorities());
    }
}