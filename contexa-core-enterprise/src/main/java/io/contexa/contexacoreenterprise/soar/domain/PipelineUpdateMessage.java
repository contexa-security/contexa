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
public class PipelineUpdateMessage {
    private String sessionId;
    private String stage;
    private int progress;
    private String message;
    private LocalDateTime timestamp;
}
