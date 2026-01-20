package io.contexa.contexamcp.events;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;


@Data
@Builder
public class ToolExecutedEvent {
    
    private final String toolName;
    private final String executionId;
    private final String userId;
    private final String requestData;
    private final String responseData;
    private final long executionTimeMs;
    private final boolean success;
    private final String errorMessage;
    private final boolean critical;
    private final Instant timestamp;
}