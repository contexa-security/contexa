package io.contexa.contexacoreenterprise.soar.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ToolExecutionMessage {
    private String sessionId;
    private String toolName;
    private String description;
    private Map<String, Object> parameters;
    private boolean requiresApproval;
    private String riskLevel;
    private LocalDateTime timestamp;
}
