package io.contexa.contexacore.security;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacommon.security.authority.AuthorityResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Slf4j
@RequiredArgsConstructor
public class UnifiedUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final AuthorityResolver authorityResolver;

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        log.error("[UnifiedUserDetailsService] findByUsernameWithGroupsRolesAndPermissions username={}", username);
        Users user = userRepository.findByUsernameWithGroupsRolesAndPermissions(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        Set<GrantedAuthority> authorities = authorityResolver.resolveAuthorities(user);
        UserDto userDto = convertToDto(user);
        return new UnifiedCustomUserDetails(userDto, authorities);
    }

    private UserDto convertToDto(Users user) {
        return UserDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .password(user.getPassword())
                .name(user.getName())
                .email(user.getEmail())
                .enabled(user.isEnabled())
                .accountLocked(user.isAccountLocked())
                .credentialsExpired(user.isCredentialsExpired())
                .externalAuthOnly(user.isExternalAuthOnly())
                .failedLoginAttempts(user.getFailedLoginAttempts())
                .lockExpiresAt(user.getLockExpiresAt())
                .lastLoginAt(user.getLastLoginAt())
                .lastLoginIp(user.getLastLoginIp())
                .passwordChangedAt(user.getPasswordChangedAt())
                .mfaEnabled(user.isMfaEnabled())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .lastMfaUsedAt(user.getLastMfaUsedAt())
                .preferredMfaFactor(user.getPreferredMfaFactor())
                .lastUsedMfaFactor(user.getLastUsedMfaFactor())
                .build();
    }
}
