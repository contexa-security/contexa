package io.contexa.contexacoreenterprise.soar.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApprovalEvent {
    private String sessionId;
    private String approvalId;
    private String toolName;
    private boolean approved;
    private String reason;
    private LocalDateTime timestamp;
}
