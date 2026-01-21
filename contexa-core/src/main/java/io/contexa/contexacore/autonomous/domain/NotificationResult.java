package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

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

    public static NotificationResult success(String requestId, String message) {
        return NotificationResult.builder()
            .requestId(requestId)
            .success(true)
            .message(message)
            .timestamp(LocalDateTime.now())
            .build();
    }

    public static NotificationResult failure(String requestId, String errorMessage) {
        return NotificationResult.builder()
            .requestId(requestId)
            .success(false)
            .message(errorMessage)
            .timestamp(LocalDateTime.now())
            .build();
    }

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