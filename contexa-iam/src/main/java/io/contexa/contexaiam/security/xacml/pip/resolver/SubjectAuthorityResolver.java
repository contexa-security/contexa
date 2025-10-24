package io.contexa.contexaiam.security.xacml.pip.resolver;

import org.springframework.security.core.GrantedAuthority;
import java.util.Set;

/**
 * 특정 타입의 주체(Subject)에 대한 모든 권한(GrantedAuthority)을 조회하는 전략 인터페이스.
 */
public interface SubjectAuthorityResolver {
    /**
     * 이 분석기가 주어진 subjectType을 지원하는지 여부를 반환합니다.
     * @param subjectType "USER", "GROUP", "ROLE" 등
     * @return 지원 여부
     */
    boolean supports(String subjectType);

    /**
     * 주어진 subjectId에 해당하는 주체의 모든 권한을 조회하여 반환합니다.
     * @param subjectId 사용자 ID, 그룹 ID, 역할 ID 등
     * @return 해당 주체가 가진 모든 GrantedAuthority Set
     */
    Set<GrantedAuthority> resolveAuthorities(Long subjectId);
}
