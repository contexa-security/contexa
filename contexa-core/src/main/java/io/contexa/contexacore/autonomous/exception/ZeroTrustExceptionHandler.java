package io.contexa.contexacore.autonomous.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.Instant;


@ControllerAdvice
@Slf4j
public class ZeroTrustExceptionHandler {

    
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

    
    @lombok.Builder
    @lombok.Getter
    public static class ZeroTrustErrorResponse {

        
        private final int status;

        
        private final String code;

        
        private final String message;

        
        private final String action;

        
        private final String resourceId;

        
        private final double riskScore;

        
        private final boolean analysisTimeout;

        
        private final Instant timestamp;
    }
}
