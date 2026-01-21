package io.contexa.contexacoreenterprise.domain.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.contexa.contexacore.utils.JpaMapConverter;
import io.contexa.contexacore.utils.JpaListConverter;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "tool_execution_contexts", indexes = {
    @Index(name = "idx_tool_context_request_id", columnList = "request_id", unique = true),
    @Index(name = "idx_tool_context_status", columnList = "status"),
    @Index(name = "idx_tool_context_created_at", columnList = "created_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class ToolExecutionContext {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "request_id", nullable = false, unique = true, length = 100)
    private String requestId;

    @Column(name = "incident_id", length = 100)
    private String incidentId;

    @Column(name = "session_id", length = 100)
    private String sessionId;

    @Column(name = "tool_name", nullable = false, length = 255)
    private String toolName;

    @Column(name = "tool_type", length = 50)
    @Builder.Default
    private String toolType = "SOAR";

    @Column(name = "tool_call_id", length = 255)
    private String toolCallId;

    @Lob
    @Column(name = "tool_arguments", columnDefinition = "TEXT")
    private String toolArguments;

    @Lob
    @Column(name = "prompt_content", columnDefinition = "TEXT", nullable = false)
    private String promptContent;

    @Lob
    @Column(name = "chat_options", columnDefinition = "TEXT")
    private String chatOptions;

    @Lob
    @Column(name = "tool_definitions", columnDefinition = "TEXT")
    private String toolDefinitions;

    @Convert(converter = JpaListConverter.class)
    @Column(name = "available_tools", columnDefinition = "TEXT")
    private List<String> availableTools;

    @Lob
    @Column(name = "chat_response", columnDefinition = "TEXT")
    private String chatResponse;

    @Column(name = "status", nullable = false, length = 20)
    @Builder.Default
    private String status = "PENDING";

    @Column(name = "execution_start_time")
    private LocalDateTime executionStartTime;

    @Column(name = "execution_end_time")
    private LocalDateTime executionEndTime;

    @Lob
    @Column(name = "execution_result", columnDefinition = "TEXT")
    private String executionResult;

    @Column(name = "execution_error", columnDefinition = "TEXT")
    private String executionError;

    @Column(name = "retry_count")
    @Builder.Default
    private Integer retryCount = 0;

    @Column(name = "max_retries")
    @Builder.Default
    private Integer maxRetries = 3;

    @Convert(converter = JpaMapConverter.class)
    @Lob
    @Column(name = "metadata", columnDefinition = "TEXT")
    private Map<String, Object> metadata;

    @Lob
    @Column(name = "pipeline_context", columnDefinition = "TEXT")
    private String pipelineContext;

    @Lob
    @Column(name = "soar_context", columnDefinition = "TEXT")
    private String soarContext;

    @Column(name = "risk_level", length = 20)
    private String riskLevel;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @JsonIgnore
    public boolean isExecutable() {
        return "APPROVED".equals(status) && !isExpired();
    }

    @JsonIgnore
    public boolean isExpired() {
        return expiresAt != null && LocalDateTime.now().isAfter(expiresAt);
    }

    @JsonIgnore
    public boolean isExecuting() {
        return "EXECUTING".equals(status);
    }

    @JsonIgnore
    public boolean isCompleted() {
        return "EXECUTED".equals(status) || "FAILED".equals(status) ||
               "CANCELLED".equals(status) || "TIMEOUT".equals(status);
    }

    @JsonIgnore
    public boolean canRetry() {
        return "FAILED".equals(status) && retryCount < maxRetries && !isExpired();
    }

    public void markExecutionStart() {
        this.status = "EXECUTING";
        this.executionStartTime = LocalDateTime.now();
    }

    public void markExecutionComplete(String result) {
        this.status = "EXECUTED";
        this.executionEndTime = LocalDateTime.now();
        this.executionResult = result;
    }

    public void markExecutionFailed(String error) {
        this.status = "FAILED";
        this.executionEndTime = LocalDateTime.now();
        this.executionError = error;
        this.retryCount++;
    }

    public void markCancelled(String reason) {
        this.status = "CANCELLED";
        this.executionError = reason;
    }

    public enum ExecutionStatus {
        PENDING("대기 중"),
        APPROVED("승인됨"),
        EXECUTING("실행 중"),
        EXECUTED("실행 완료"),
        FAILED("실행 실패"),
        CANCELLED("취소됨"),
        TIMEOUT("타임아웃");
        
        private final String description;
        
        ExecutionStatus(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
}