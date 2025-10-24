package io.contexa.contexacore.domain;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * SOAR 인시던트
 * 
 * 보안 인시던트 정보를 캡슐화합니다.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SoarIncident implements Serializable {
    
    private String incidentId;
    private String organizationId;
    private String title;
    private String description;
    private IncidentStatus status;
    private IncidentSeverity severity;
    private IncidentType type;
    private LocalDateTime detectedAt;
    private LocalDateTime reportedAt;
    private LocalDateTime resolvedAt;
    private String reporter;
    private String assignee;
    private LocalDateTime createdAt;
    private String threatType;
    private List<String> affectedAssets;
    private Map<String, Object> indicators;
    private Map<String, Object> evidence;
    private List<String> actionsTaken;
    private String resolution;
    private Map<String, Object> metadata;
    
    /**
     * 인시던트 상태
     */
    public enum IncidentStatus {
        NEW("신규"),
        INVESTIGATING("조사 중"),
        IN_PROGRESS("진행 중"),
        CONTAINED("격리됨"),
        MITIGATED("완화됨"),
        ERADICATED("제거됨"),
        RECOVERED("복구됨"),
        RESOLVED("해결됨"),
        CLOSED("종료"),
        FALSE_POSITIVE("오탐");
        
        private final String description;
        
        IncidentStatus(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 인시던트 심각도
     */
    public enum IncidentSeverity {
        CRITICAL("치명적"),
        HIGH("높음"),
        MEDIUM("중간"),
        LOW("낮음"),
        INFO("정보");
        
        private final String description;
        
        IncidentSeverity(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 인시던트 유형
     */
    public enum IncidentType {
        MALWARE("악성코드"),
        RANSOMWARE("랜섬웨어"),
        PHISHING("피싱"),
        DATA_BREACH("데이터 유출"),
        UNAUTHORIZED_ACCESS("무단 접근"),
        DOS_ATTACK("서비스 거부 공격"),
        INSIDER_THREAT("내부자 위협"),
        VULNERABILITY("취약점"),
        COMPLIANCE_VIOLATION("컴플라이언스 위반"),
        OTHER("기타");
        
        private final String description;
        
        IncidentType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
}