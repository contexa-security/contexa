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

/**
 * Tool Execution Context Entity
 * 
 * 도구 실행에 필요한 모든 컨텍스트 정보를 영속화합니다.
 * 비동기 모드에서 나중에 승인받았을 때 도구를 실행할 수 있도록
 * Spring AI의 Prompt와 ChatResponse 정보를 저장합니다.
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
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
    
    /**
     * 승인 요청 ID
     * SoarApprovalRequest와 1:1 관계
     */
    @Column(name = "request_id", nullable = false, unique = true, length = 100)
    private String requestId;
    
    /**
     * 인시던트 ID
     */
    @Column(name = "incident_id", length = 100)
    private String incidentId;
    
    /**
     * 세션 ID
     */
    @Column(name = "session_id", length = 100)
    private String sessionId;
    
    /**
     * 도구 이름
     * 실행할 SOAR 도구의 이름
     */
    @Column(name = "tool_name", nullable = false, length = 255)
    private String toolName;
    
    /**
     * 도구 타입
     * MCP, SOAR, BUILTIN 등
     */
    @Column(name = "tool_type", length = 50)
    @Builder.Default
    private String toolType = "SOAR";
    
    /**
     * 도구 호출 ID
     * Spring AI ToolCall의 ID
     */
    @Column(name = "tool_call_id", length = 255)
    private String toolCallId;
    
    /**
     * 도구 인자 (JSON)
     * 도구 호출 시 전달될 파라미터
     */
    @Lob
    @Column(name = "tool_arguments", columnDefinition = "TEXT")
    private String toolArguments;
    
    /**
     * 프롬프트 내용 (JSON)
     * Spring AI Prompt의 Message들을 JSON 배열로 저장
     * [{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]
     */
    @Lob
    @Column(name = "prompt_content", columnDefinition = "TEXT", nullable = false)
    private String promptContent;
    
    /**
     * ChatOptions (JSON)
     * 도구 실행에 필요한 ChatOptions 설정
     * temperature, model, toolNames 등
     */
    @Lob
    @Column(name = "chat_options", columnDefinition = "TEXT")
    private String chatOptions;
    
    /**
     * 도구 정의 (JSON)
     * ToolCallback 정의 정보
     * name, description, parameters 등
     */
    @Lob
    @Column(name = "tool_definitions", columnDefinition = "TEXT")
    private String toolDefinitions;
    
    /**
     * 도구 이름 목록
     * 사용 가능한 모든 도구 이름
     */
    @Convert(converter = JpaListConverter.class)
    @Column(name = "available_tools", columnDefinition = "TEXT")
    private List<String> availableTools;
    
    /**
     * ChatResponse (JSON)
     * 이전 ChatResponse 정보 (도구 호출 정보 포함)
     * 도구 재실행 시 필요
     */
    @Lob
    @Column(name = "chat_response", columnDefinition = "TEXT")
    private String chatResponse;
    
    /**
     * 실행 상태
     * PENDING: 대기 중
     * APPROVED: 승인됨
     * EXECUTING: 실행 중
     * EXECUTED: 실행 완료
     * FAILED: 실행 실패
     * CANCELLED: 취소됨
     * TIMEOUT: 타임아웃
     */
    @Column(name = "status", nullable = false, length = 20)
    @Builder.Default
    private String status = "PENDING";
    
    /**
     * 실행 시작 시간
     */
    @Column(name = "execution_start_time")
    private LocalDateTime executionStartTime;
    
    /**
     * 실행 종료 시간
     */
    @Column(name = "execution_end_time")
    private LocalDateTime executionEndTime;
    
    /**
     * 실행 결과 (JSON)
     * ToolExecutionResult를 JSON으로 저장
     */
    @Lob
    @Column(name = "execution_result", columnDefinition = "TEXT")
    private String executionResult;
    
    /**
     * 실행 오류
     */
    @Column(name = "execution_error", columnDefinition = "TEXT")
    private String executionError;
    
    /**
     * 재시도 횟수
     */
    @Column(name = "retry_count")
    @Builder.Default
    private Integer retryCount = 0;
    
    /**
     * 최대 재시도 횟수
     */
    @Column(name = "max_retries")
    @Builder.Default
    private Integer maxRetries = 3;
    
    /**
     * 메타데이터 (JSON)
     * 추가 컨텍스트 정보
     */
    @Convert(converter = JpaMapConverter.class)
    @Lob
    @Column(name = "metadata", columnDefinition = "TEXT")
    private Map<String, Object> metadata;
    
    /**
     * Pipeline 컨텍스트 (JSON)
     * PipelineExecutionContext의 데이터
     */
    @Lob
    @Column(name = "pipeline_context", columnDefinition = "TEXT")
    private String pipelineContext;
    
    /**
     * SOAR 컨텍스트 (JSON)
     * SoarContext의 데이터
     */
    @Lob
    @Column(name = "soar_context", columnDefinition = "TEXT")
    private String soarContext;
    
    /**
     * 위험 수준
     * CRITICAL, HIGH, MEDIUM, LOW
     */
    @Column(name = "risk_level", length = 20)
    private String riskLevel;
    
    /**
     * 만료 시간
     * 이 시간까지 실행되지 않으면 자동 취소
     */
    @Column(name = "expires_at")
    private LocalDateTime expiresAt;
    
    /**
     * 생성 시간
     */
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    /**
     * 수정 시간
     */
    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
    
    /**
     * 실행 가능한지 확인
     *
     * @return 실행 가능하면 true
     */
    @JsonIgnore
    public boolean isExecutable() {
        return "APPROVED".equals(status) && !isExpired();
    }

    /**
     * 만료되었는지 확인
     *
     * @return 만료되었으면 true
     */
    @JsonIgnore
    public boolean isExpired() {
        return expiresAt != null && LocalDateTime.now().isAfter(expiresAt);
    }

    /**
     * 실행 중인지 확인
     *
     * @return 실행 중이면 true
     */
    @JsonIgnore
    public boolean isExecuting() {
        return "EXECUTING".equals(status);
    }

    /**
     * 완료되었는지 확인
     *
     * @return 완료되었으면 true
     */
    @JsonIgnore
    public boolean isCompleted() {
        return "EXECUTED".equals(status) || "FAILED".equals(status) ||
               "CANCELLED".equals(status) || "TIMEOUT".equals(status);
    }

    /**
     * 재시도 가능한지 확인
     *
     * @return 재시도 가능하면 true
     */
    @JsonIgnore
    public boolean canRetry() {
        return "FAILED".equals(status) && retryCount < maxRetries && !isExpired();
    }
    
    /**
     * 실행 시작 표시
     */
    public void markExecutionStart() {
        this.status = "EXECUTING";
        this.executionStartTime = LocalDateTime.now();
    }
    
    /**
     * 실행 완료 표시
     * 
     * @param result 실행 결과 JSON
     */
    public void markExecutionComplete(String result) {
        this.status = "EXECUTED";
        this.executionEndTime = LocalDateTime.now();
        this.executionResult = result;
    }
    
    /**
     * 실행 실패 표시
     * 
     * @param error 오류 메시지
     */
    public void markExecutionFailed(String error) {
        this.status = "FAILED";
        this.executionEndTime = LocalDateTime.now();
        this.executionError = error;
        this.retryCount++;
    }
    
    /**
     * 취소 표시
     * 
     * @param reason 취소 사유
     */
    public void markCancelled(String reason) {
        this.status = "CANCELLED";
        this.executionError = reason;
    }
    
    /**
     * 실행 상태 enum
     */
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