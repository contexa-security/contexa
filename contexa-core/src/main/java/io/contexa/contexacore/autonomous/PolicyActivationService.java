package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.autonomous.domain.ActivationResult;

/**
 * PolicyActivationService - 정책 활성화 서비스 인터페이스
 *
 * <p>
 * Enterprise 모듈에서 정책 활성화 기능을 제공하는 인터페이스입니다.
 * Spring Boot AutoConfiguration을 통해 자동으로 주입됩니다.
 * </p>
 *
 * @since 0.1.0-ALPHA
 */
public interface PolicyActivationService {

    /**
     * 정책 활성화
     *
     * @param proposalId 제안 ID
     * @param approvedBy 승인자
     * @return 활성화 결과
     */
    ActivationResult activatePolicy(Long proposalId, String approvedBy);

    /**
     * 정책 비활성화
     *
     * @param proposalId 제안 ID
     * @param deactivatedBy 비활성화 요청자
     * @param reason 비활성화 이유
     * @return 비활성화 성공 여부
     */
    boolean deactivatePolicy(Long proposalId, String deactivatedBy, String reason);
}
