package io.contexa.contexacore.autonomous.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.Instant;

/**
 * Zero Trust 보안 아키텍처 통합 예외 처리기
 *
 * ZeroTrustAccessDeniedException을 처리하여 표준화된 에러 응답을 반환한다.
 * action 유형에 따른 HTTP 상태 코드 매핑을 지원한다.
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@ControllerAdvice
@Slf4j
public class ZeroTrustExceptionHandler {

    /**
     * ZeroTrustAccessDeniedException 처리
     *
     * @param ex 예외
     * @return 표준화된 에러 응답
     */
    @ExceptionHandler(ZeroTrustAccessDeniedException.class)
    public ResponseEntity<ZeroTrustErrorResponse> handleZeroTrustDenied(
            ZeroTrustAccessDeniedException ex) {

        log.warn("Zero Trust 접근 거부 - action: {}, resource: {}, risk: {}, reason: {}",
            ex.getAction(), ex.getResourceId(), ex.getRiskScore(), ex.getReason());

        ZeroTrustErrorResponse response = ZeroTrustErrorResponse.builder()
            .status(ex.getHttpStatus())
            .code(ex.getErrorCode())
            .message(ex.getReason())
            .action(ex.getAction())
            .resourceId(ex.getResourceId())
            .riskScore(ex.getRiskScore())
            .analysisTimeout(ex.isAnalysisTimeout())
            .timestamp(Instant.now())
            .build();

        return ResponseEntity
            .status(response.getStatus())
            .body(response);
    }

    /**
     * AnomalyDetectedException 처리 (기존 예외 호환)
     *
     * @param ex 예외
     * @return 표준화된 에러 응답
     */
    @ExceptionHandler(AnomalyDetectedException.class)
    public ResponseEntity<ZeroTrustErrorResponse> handleAnomalyDetected(
            AnomalyDetectedException ex) {

        log.warn("이상 탐지 접근 거부 - message: {}", ex.getMessage());

        ZeroTrustErrorResponse response = ZeroTrustErrorResponse.builder()
            .status(403)
            .code("ZERO_TRUST_ANOMALY_DETECTED")
            .message(ex.getMessage())
            .action("BLOCK")
            .resourceId("unknown")
            .riskScore(1.0)
            .analysisTimeout(false)
            .timestamp(Instant.now())
            .build();

        return ResponseEntity
            .status(403)
            .body(response);
    }

    /**
     * Zero Trust 에러 응답 DTO
     */
    @lombok.Builder
    @lombok.Getter
    public static class ZeroTrustErrorResponse {

        /**
         * HTTP 상태 코드
         */
        private final int status;

        /**
         * 에러 코드 (예: ZERO_TRUST_BLOCK)
         */
        private final String code;

        /**
         * 에러 메시지 (사용자 표시용)
         */
        private final String message;

        /**
         * LLM action
         */
        private final String action;

        /**
         * 접근 시도한 리소스 ID
         */
        private final String resourceId;

        /**
         * 위험도 점수
         */
        private final double riskScore;

        /**
         * 분석 타임아웃 여부
         */
        private final boolean analysisTimeout;

        /**
         * 발생 시각
         */
        private final Instant timestamp;
    }
}
