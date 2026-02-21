package io.contexa.contexacoreenterprise.soar.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SimulationStartResponse {
    private String sessionId;
    private String conversationId;
    private String status;
    private String message;
    private String finalResponse;
    private List<String> pipelineStages;
    private LocalDateTime timestamp;
}
