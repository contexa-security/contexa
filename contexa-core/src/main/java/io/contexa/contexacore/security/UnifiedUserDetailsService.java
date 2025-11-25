package io.contexa.contexacore.security;

import io.contexa.contexacommon.dto.UserDto;
import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.security.authority.RoleAuthority;
import io.contexa.contexacommon.security.authority.PermissionAuthority;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
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

/**
 * 통합 UserDetailsService
 *
 * IdentityUserDetailsService 패턴 채택:
 * 1. Users 엔티티 조회
 * 2. 권한 초기화 (Service 계층)
 * 3. Users → UserDto 변환 (수동 매핑, ModelMapper 제거)
 * 4. UnifiedCustomUserDetails 생성
 *
 * IAM 권한 모델 채택:
 * - RoleAuthority + PermissionAuthority (세밀한 제어)
 *
 * AI 기능:
 * - Trust Tier 동적 권한 조정 (선택적)
 * - HCAD 이상 탐지 (선택적)
 */
@Slf4j
@RequiredArgsConstructor
public class UnifiedUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final SecurityTrustTierProperties trustTierProperties;
    private final SecurityAnomalyDetectionProperties anomalyDetectionProperties;
    private final RedisTemplate<String, Object> redisTemplate;  // Optional
    private final NotificationService notificationService;  // Optional
    private final AuditLogRepository auditLogRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 1. DB에서 사용자 조회 (JOIN FETCH로 그래프 전체 로드)
        Users user = userRepository.findByUsernameWithGroupsRolesAndPermissions(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        // 2. 권한 초기화 (RoleAuthority + PermissionAuthority)
        Set<GrantedAuthority> authorities = initializeAuthorities(user);

        // 3. Users → UserDto 변환 (수동 매핑, Redis 직렬화 안전)
        UserDto userDto = convertToDto(user);

        // 4. HCAD 이상 탐지 (Feature Flag)
        if (anomalyDetectionProperties.isEnabled()) {
            checkAndHandleAnomalyBlocking(username);
        }

        // 5. Trust Tier 권한 조정 (Feature Flag)
        if (trustTierProperties.isEnabled() && redisTemplate != null) {
            adjustAuthoritiesByTrustTier(userDto, authorities);
        }

        // 6. UnifiedCustomUserDetails 생성
        return new UnifiedCustomUserDetails(userDto, authorities);
    }

    /**
     * Users 엔티티로부터 권한 초기화 (IAM 패턴)
     *
     * 엔티티 그래프: Users → UserGroup → Group → GroupRole → Role → RolePermission → Permission
     */
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
                    // 1. RoleAuthority 추가
                    authorities.add(new RoleAuthority(role));

                    // 2. Permission 추가
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

    /**
     * Users 엔티티 → UserDto 변환 (수동 매핑, ModelMapper 제거)
     *
     * Redis 직렬화 안전을 위해 DTO 사용
     */
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

    /**
     * HCAD 이상 탐지 및 차단
     */
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

                // Audit Log 기록
                AuditLog auditLog = AuditLog.builder()
                        .principalName(username)
                        .action("AUTHENTICATION_BLOCKED")
                        .decision("FAILURE")
                        .reason("Anomaly detected: " + anomalyData)
                        .build();
                auditLogRepository.save(auditLog);

                // 멀티 채널 알림 (Feature Flag)
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

                // 차단 설정이 활성화된 경우에만 차단
                if (anomalyDetectionProperties.isBlockOnAnomaly()) {
                    throw new AnomalyDetectedException("Authentication blocked due to anomaly");
                }
            }
        }
    }

    /**
     * Trust Tier 기반 권한 조정
     *
     * UserDto에 조정된 권한을 설정 (Redis 직렬화 안전)
     */
    private void adjustAuthoritiesByTrustTier(UserDto userDto, Set<GrantedAuthority> originalAuthorities) {
        Double trustScore = getTrustScore(userDto.getUsername());
        if (trustScore == null) {
            trustScore = trustTierProperties.getDefaults().getTrustScore();
        }

        String trustTier = determineTrustTier(trustScore);
        Set<GrantedAuthority> adjustedAuthorities = filterAuthoritiesByTier(originalAuthorities, trustTier);

        // UserDto에 Trust Tier 메타데이터 설정
        userDto.setAuthorities(adjustedAuthorities);  // 조정된 권한으로 덮어쓰기
        userDto.setTrustScore(trustScore);
        userDto.setTrustTier(trustTier);

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("originalAuthorityCount", originalAuthorities.size());
        metadata.put("adjustedAuthorityCount", adjustedAuthorities.size());
        metadata.put("filteredCount", originalAuthorities.size() - adjustedAuthorities.size());
        userDto.setTrustMetadata(metadata);

        // Redis 캐시
        String key = String.format("zerotrust:user:trust_tier:%s", userDto.getUsername());
        redisTemplate.opsForValue().set(
                key,
                trustTier,
                trustTierProperties.getCache().getTtlMinutes(),
                TimeUnit.MINUTES
        );

        log.info("Trust Tier applied for user {}: {} (score: {})",
                userDto.getUsername(), trustTier, trustScore);
    }

    /**
     * Trust Score 조회
     */
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

    /**
     * Trust Tier 결정
     */
    private String determineTrustTier(Double trustScore) {
        if (trustScore >= trustTierProperties.getThresholds().getTier1()) {
            return "TIER_1";
        }
        if (trustScore >= trustTierProperties.getThresholds().getTier2()) {
            return "TIER_2";
        }
        if (trustScore >= trustTierProperties.getThresholds().getTier3()) {
            return "TIER_3";
        }
        return "TIER_4";
    }

    /**
     * Trust Tier 기반 권한 필터링
     */
    private Set<GrantedAuthority> filterAuthoritiesByTier(
            Set<GrantedAuthority> authorities, String tier) {
        Set<GrantedAuthority> filtered = new HashSet<>();

        for (GrantedAuthority authority : authorities) {
            String auth = authority.getAuthority().toUpperCase();

            switch (tier) {
                case "TIER_1":
                    filtered.add(authority);
                    break;

                case "TIER_2":
                    if (!auth.contains("ADMIN")
                        && !auth.contains("DELETE")
                        && !auth.contains("MODIFY_CRITICAL")) {
                        filtered.add(authority);
                    }
                    break;

                case "TIER_3":
                    if (auth.contains("READ")
                        || auth.contains("VIEW")
                        || auth.contains("LIST")) {
                        filtered.add(authority);
                    }
                    break;

                case "TIER_4":
                    if (auth.equals("ROLE_MINIMAL")
                        || auth.equals("PERMISSION_VIEW_PROFILE")) {
                        filtered.add(authority);
                    }
                    break;
            }
        }

        return filtered;
    }
}
