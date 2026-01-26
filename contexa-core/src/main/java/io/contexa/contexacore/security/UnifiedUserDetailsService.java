package io.contexa.contexacore.security;

import io.contexa.contexacommon.dto.UserDto;
import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.security.authority.RoleAuthority;
import io.contexa.contexacommon.security.authority.PermissionAuthority;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacommon.security.TrustTier;
import io.contexa.contexacore.autonomous.notification.NotificationService;
import io.contexa.contexacore.autonomous.exception.AnomalyDetectedException;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.concurrent.TimeUnit;

@Slf4j
@RequiredArgsConstructor
public class UnifiedUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        
        Users user = userRepository.findByUsernameWithGroupsRolesAndPermissions(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        Set<GrantedAuthority> authorities = initializeAuthorities(user);
        UserDto userDto = convertToDto(user);
        return new UnifiedCustomUserDetails(userDto, authorities);
    }

    private Set<GrantedAuthority> initializeAuthorities(Users user) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        Optional.ofNullable(user.getUserGroups())
                .orElse(Collections.emptySet())
                .stream()
                .map(UserGroup::getGroup)
                .filter(Objects::nonNull)
                .flatMap(group -> Optional.ofNullable(group.getGroupRoles())
                        .orElse(Collections.emptySet()).stream())
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

    private UserDto convertToDto(Users user) {
        return UserDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .password(user.getPassword())
                .name(user.getName())
                .mfaEnabled(user.isMfaEnabled())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .lastMfaUsedAt(user.getLastMfaUsedAt())
                .preferredMfaFactor(user.getPreferredMfaFactor())
                .lastUsedMfaFactor(user.getLastUsedMfaFactor())
                .build();
    }
}
