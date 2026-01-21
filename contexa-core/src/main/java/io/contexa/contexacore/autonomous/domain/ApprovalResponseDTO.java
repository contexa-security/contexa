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
public class ApprovalResponseDTO {
    
    private Long proposalId;
    private boolean success;
    private String message;
    private boolean workflowComplete;
    private boolean activated;
    private LocalDateTime timestamp;
}