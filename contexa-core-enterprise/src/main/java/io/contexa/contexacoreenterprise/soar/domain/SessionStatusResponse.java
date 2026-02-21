package io.contexa.contexacoreenterprise.soar.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SessionStatusResponse {
    private String sessionId;
    private String status;
    private String currentStage;
    private int progress;
    private List<String> executedTools;
    private List<String> pendingApprovals;
    private Map<String, Boolean> mcpServersStatus;
    private LocalDateTime timestamp;
}
