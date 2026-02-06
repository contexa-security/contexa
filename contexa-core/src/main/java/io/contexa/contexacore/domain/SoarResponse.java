package io.contexa.contexacore.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class SoarResponse extends AIResponse {

    private String analysisResult;

    private SessionState sessionState;

    @JsonSetter(nulls = Nulls.AS_EMPTY)
    @JsonDeserialize(using = StringToListDeserializer.class)
    private List<String> executedTools = new ArrayList<>();

    @JsonSetter(nulls = Nulls.AS_EMPTY)
    @JsonDeserialize(using = StringToListDeserializer.class)
    private List<String> recommendations = new ArrayList<>();

    private String summary;

    private String incidentId;

    private SoarContext.ThreatLevel threatLevel;

    private String sessionId;

    private LocalDateTime timestamp;

    private Map<String, Object> metadata;

    public SoarResponse() {
        this.timestamp = LocalDateTime.now();
        this.sessionState = SessionState.INITIALIZED;
        this.withExecutionTime(LocalDateTime.now());
    }

    public SoarResponse(String requestId, ExecutionStatus status) {
        this.timestamp = LocalDateTime.now();
        this.sessionState = SessionState.INITIALIZED;
        this.withExecutionTime(LocalDateTime.now());
    }
}