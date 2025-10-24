package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Notification Result Domain Object
 * 
 * 알림 결과를 나타내는 도메인 객체
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NotificationResult {
    
    private String requestId;
    private boolean success;
    private String message;
    private String errorCode;
    private LocalDateTime timestamp;
    
    /**
     * 성공 결과 생성
     */
    public static NotificationResult success(String requestId, String message) {
        return NotificationResult.builder()
            .requestId(requestId)
            .success(true)
            .message(message)
            .timestamp(LocalDateTime.now())
            .build();
    }
    
    /**
     * 실패 결과 생성
     */
    public static NotificationResult failure(String requestId, String errorMessage) {
        return NotificationResult.builder()
            .requestId(requestId)
            .success(false)
            .message(errorMessage)
            .timestamp(LocalDateTime.now())
            .build();
    }
    
    /**
     * 에러 코드와 함께 실패 결과 생성
     */
    public static NotificationResult failure(String requestId, String errorCode, String errorMessage) {
        return NotificationResult.builder()
            .requestId(requestId)
            .success(false)
            .errorCode(errorCode)
            .message(errorMessage)
            .timestamp(LocalDateTime.now())
            .build();
    }
}