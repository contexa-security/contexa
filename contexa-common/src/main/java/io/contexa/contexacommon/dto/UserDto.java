package io.contexa.contexacommon.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Map;

/**
 * 통합 UserDto
 *
 * Redis 직렬화 안전을 위해 JPA 엔티티가 아닌 DTO 사용
 * Identity와 IAM의 UserDto를 통합하여 모든 필수 필드 포함
 *
 * 변경 내역:
 * - Users 엔티티의 모든 기본 필드 포함
 * - age 필드 제거 (Users 엔티티에 없음)
 * - Trust Tier 메타데이터 필드 추가
 * - Serializable 구현으로 Redis 직렬화 지원
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto implements Serializable {

    private static final long serialVersionUID = 1L;

    // Users 엔티티의 기본 필드
    private Long id;
    private String username;
    private String password;
    private String name;
    private boolean mfaEnabled;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime lastMfaUsedAt;
    private String preferredMfaFactor;
    private String lastUsedMfaFactor;

    // 권한 정보 (외부에서 주입)
    private Collection<? extends GrantedAuthority> authorities;

    // IAM 전용 필드
    private java.util.List<String> roles;
    private java.util.List<String> permissions;
    private java.util.List<Long> selectedGroupIds;

    // AI Trust Tier 메타데이터 (선택적)
    private Double trustScore;
    private String trustTier;
    private Map<String, Object> trustMetadata;
}
