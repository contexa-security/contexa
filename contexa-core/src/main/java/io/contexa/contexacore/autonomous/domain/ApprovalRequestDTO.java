package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;

/**
 * 승인 요청 DTO
 * 
 * @author contexa
 * @since 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApprovalRequestDTO {
    
    @NotBlank(message = "Approver ID is required")
    private String approverId;
    
    private String requestId; // 특정 승인 요청 ID (다단계 승인 시)
    
    private String comments;
}