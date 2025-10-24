package io.contexa.contexaiam.admin.support.translation;

import io.contexa.contexaiam.domain.entity.policy.Policy;

/**
 * 시스템 내부의 기술 용어를 UI에 표시하기 위한 비즈니스 용어로 변환하는 책임을 집니다.
 */
public interface TerminologyTranslationService {
    /**
     * 'PERM_USER_READ' 같은 내부 권한 이름을 '사용자 정보 읽기'와 같은 설명으로 변환합니다.
     * @param permissionName 내부 권한 이름
     * @return 사용자 친화적 설명
     */
    String generatePermissionDescription(String permissionName);

    /**
     * 복잡한 SpEL 규칙으로 구성된 Policy 객체를 "관리자 그룹은 모든 리소스에 접근 가능" 과 같은 한 줄 요약으로 생성합니다.
     * (기존 PolicyEnrichmentService의 역할을 이 인터페이스가 명확히 정의)
     * @param policy 요약할 Policy 객체
     * @return 자연어 정책 요약
     */
    String summarizePolicy(Policy policy);
}
