package io.contexa.contexacore.autonomous.domain;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;


@Builder
@Data
public class ActivationResult {

    
    private Long proposalId;

    
    private Long versionId;

    
    private boolean success;

    
    private String message;

    
    private LocalDateTime timestamp;

    
    public static ActivationResult success(Long proposalId, Long versionId) {
        return ActivationResult.builder()
            .proposalId(proposalId)
            .versionId(versionId)
            .success(true)
            .message("Successfully activated")
            .timestamp(LocalDateTime.now())
            .build();
    }

    
    public static ActivationResult failure(Long proposalId, String message) {
        return ActivationResult.builder()
            .proposalId(proposalId)
            .success(false)
            .message(message)
            .timestamp(LocalDateTime.now())
            .build();
    }
}
