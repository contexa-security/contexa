package io.contexa.contexacore.autonomous.domain;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 정책 활성화 결과
 *
 * <p>
 * PolicyActivationService의 정책 활성화/비활성화 결과를 담는 DTO입니다.
 * </p>
 *
 * @since 0.1.0-ALPHA
 */
@Builder
@Data
public class ActivationResult {

    /**
     * 제안 ID
     */
    private Long proposalId;

    /**
     * 버전 ID
     */
    private Long versionId;

    /**
     * 성공 여부
     */
    private boolean success;

    /**
     * 결과 메시지
     */
    private String message;

    /**
     * 타임스탬프
     */
    private LocalDateTime timestamp;

    /**
     * 성공 결과 생성
     *
     * @param proposalId 제안 ID
     * @param versionId 버전 ID
     * @return 성공 결과
     */
    public static ActivationResult success(Long proposalId, Long versionId) {
        return ActivationResult.builder()
            .proposalId(proposalId)
            .versionId(versionId)
            .success(true)
            .message("Successfully activated")
            .timestamp(LocalDateTime.now())
            .build();
    }

    /**
     * 실패 결과 생성
     *
     * @param proposalId 제안 ID
     * @param message 실패 메시지
     * @return 실패 결과
     */
    public static ActivationResult failure(Long proposalId, String message) {
        return ActivationResult.builder()
            .proposalId(proposalId)
            .success(false)
            .message(message)
            .timestamp(LocalDateTime.now())
            .build();
    }
}
