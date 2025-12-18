package io.contexa.contexaiam.security.xacml.prp;

import io.contexa.contexaiam.domain.entity.policy.Policy;

import java.util.List;

/**
 * 정책 조회 지점 (Policy Retrieval Point)
 *
 * XACML PRP 역할을 수행하며, 정책 조회 및 캐시 관리를 담당합니다.
 * ContexaCacheService를 통한 2-Level 캐시(L1 Caffeine + L2 Redis)를 사용합니다.
 *
 * @since 0.1.0-ALPHA
 */
public interface PolicyRetrievalPoint {

    /**
     * 모든 URL 정책 조회
     *
     * @return URL 타입의 정책 목록
     */
    List<Policy> findUrlPolicies();

    /**
     * URL 정책 캐시 무효화
     */
    void clearUrlPoliciesCache();

    /**
     * 메서드 정책 조회 (모든 phase)
     *
     * @param methodIdentifier 메서드 식별자 (클래스명.메서드명(파라미터타입))
     * @return 해당 메서드의 모든 정책 목록
     */
    List<Policy> findMethodPolicies(String methodIdentifier);

    /**
     * 메서드 정책 캐시 무효화
     */
    void clearMethodPoliciesCache();

    /**
     * phase 기반 메서드 정책 조회
     *
     * @param methodIdentifier 메서드 식별자 (클래스명.메서드명(파라미터타입))
     * @param phase 인가 phase (PRE_AUTHORIZE, POST_AUTHORIZE)
     * @return 해당 phase의 정책 목록
     */
    List<Policy> findMethodPolicies(String methodIdentifier, String phase);
}