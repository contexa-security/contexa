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
public class PolicyOperationResultDTO {
    
    private Long policyId;
    private String operation;
    private boolean success;
    private String message;
    private LocalDateTime timestamp;
}