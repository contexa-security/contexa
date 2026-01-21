package io.contexa.contexacore.security;

import io.contexa.contexacommon.dto.UserDto;
import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.security.authority.RoleAuthority;
import io.contexa.contexacommon.security.authority.PermissionAuthority;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacommon.security.TrustTier;
import io.contexa.contexacommon.properties.SecurityTrustTierProperties;
import io.contexa.contexacommon.properties.SecurityAnomalyDetectionProperties;
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
    private final SecurityTrustTierProperties trustTierProperties;
    private final SecurityAnomalyDetectionProperties anomalyDetectionProperties;
    private final RedisTemplate<String, Object> redisTemplate;  
    private final NotificationService notificationService;  
    private final AuditLogRepository auditLogRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        
        Users user = userRepository.findByUsernameWithGroupsRolesAndPermissions(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        Set<GrantedAuthority> authorities = initializeAuthorities(user);

        UserDto userDto = convertToDto(user);

        if (anomalyDetectionProperties.isEnabled()) {
            checkAndHandleAnomalyBlocking(username);
        }

        if (trustTierProperties.isEnabled() && redisTemplate != null) {
            adjustAuthoritiesByTrustTier(userDto, authorities);
        }

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

    private void checkAndHandleAnomalyBlocking(String username) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getDetails() == null) {
            return;
        }

        Object details = authentication.getDetails();
        if (details instanceof Map) {
            Map<String, Object> detailsMap = (Map<String, Object>) details;
            Object anomalyData = detailsMap.get("HCAD_ANOMALY_INFO");

            if (anomalyData != null) {
                log.warn("[Zero Trust] Anomaly detected for user: {}", username);

                AuditLog auditLog = AuditLog.builder()
                        .principalName(username)
                        .action("AUTHENTICATION_BLOCKED")
                        .decision("FAILURE")
                        .reason("Anomaly detected: " + anomalyData)
                        .build();
                auditLogRepository.save(auditLog);

                if (anomalyDetectionProperties.getNotification().isEnabled() && notificationService != null) {
                    Map<String, Object> notificationData = new HashMap<>();
                    notificationData.put("username", username);
                    notificationData.put("anomalyDetails", anomalyData);
                    notificationData.put("timestamp", java.time.Instant.now());

                    notificationService.sendNotification(
                            "AUTHENTICATION_BLOCKED",
                            "Authentication blocked due to anomaly for user: " + username,
                            notificationData,
                            io.contexa.contexacore.autonomous.notification.NotificationService.Priority.HIGH
                    );
                }

                if (anomalyDetectionProperties.isBlockOnAnomaly()) {
                    throw new AnomalyDetectedException("Authentication blocked due to anomaly");
                }
            }
        }
    }

    private void adjustAuthoritiesByTrustTier(UserDto userDto, Set<GrantedAuthority> originalAuthorities) {
        Double trustScore = getTrustScore(userDto.getUsername());
        if (trustScore == null) {
            trustScore = trustTierProperties.getDefaults().getTrustScore();
        }

        TrustTier trustTier = determineTrustTier(trustScore);
        Set<GrantedAuthority> adjustedAuthorities = filterAuthoritiesByTier(originalAuthorities, trustTier);

        userDto.setAuthorities(adjustedAuthorities);  
        userDto.setTrustScore(trustScore);
        userDto.setTrustTier(trustTier.name());  

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("originalAuthorityCount", originalAuthorities.size());
        metadata.put("adjustedAuthorityCount", adjustedAuthorities.size());
        metadata.put("filteredCount", originalAuthorities.size() - adjustedAuthorities.size());
        userDto.setTrustMetadata(metadata);

        if (redisTemplate != null) {
            String key = String.format("zerotrust:user:trust_tier:%s", userDto.getUsername());
            redisTemplate.opsForValue().set(
                    key,
                    trustTier.name(),  
                    trustTierProperties.getCache().getTtlMinutes(),
                    TimeUnit.MINUTES
            );
        }

            }

    private Double getTrustScore(String username) {
        if (redisTemplate == null) {
            return null;
        }

        String key = ZeroTrustRedisKeys.threatScore(username);
        Double threatScore = (Double) redisTemplate.opsForValue().get(key);
        if (threatScore == null) {
            return null;
        }
        return 1.0 - threatScore;
    }

    private TrustTier determineTrustTier(Double trustScore) {
        return TrustTier.fromScore(trustScore, trustTierProperties.getThresholds());
    }

    private Set<GrantedAuthority> filterAuthoritiesByTier(
            Set<GrantedAuthority> authorities, TrustTier tier) {
        Set<GrantedAuthority> filtered = new HashSet<>();

        for (GrantedAuthority authority : authorities) {
            String auth = authority.getAuthority().toUpperCase();

            switch (tier) {
                case TIER_1:
                    
                    filtered.add(authority);
                    break;

                case TIER_2:
                    
                    boolean excludedByTier2 = trustTierProperties.getFilterRules().getTier2ExcludeKeywords()
                            .stream()
                            .anyMatch(auth::contains);
                    if (!excludedByTier2) {
                        filtered.add(authority);
                    }
                    break;

                case TIER_3:
                    
                    boolean allowedByTier3 = trustTierProperties.getFilterRules().getTier3AllowKeywords()
                            .stream()
                            .anyMatch(auth::contains);
                    if (allowedByTier3) {
                        filtered.add(authority);
                    }
                    break;

                case TIER_4:
                    
                    boolean allowedByTier4 = trustTierProperties.getFilterRules().getTier4AllowAuthorities()
                            .stream()
                            .anyMatch(allowed -> auth.equals(allowed.toUpperCase()));
                    if (allowedByTier4) {
                        filtered.add(authority);
                    }
                    break;
            }
        }

        return filtered;
    }
}
