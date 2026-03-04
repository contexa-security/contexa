package io.contexa.contexacore.domain;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

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

    public enum IncidentStatus {
        NEW("New"),
        INVESTIGATING("Investigating"),
        IN_PROGRESS("In Progress"),
        CONTAINED("Contained"),
        MITIGATED("Mitigated"),
        ERADICATED("Eradicated"),
        RECOVERED("Recovered"),
        RESOLVED("Resolved"),
        CLOSED("Closed"),
        FALSE_POSITIVE("False Positive");
        
        private final String description;
        
        IncidentStatus(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }

    public enum IncidentSeverity {
        CRITICAL("Critical"),
        HIGH("High"),
        MEDIUM("Medium"),
        LOW("Low"),
        INFO("Info");
        
        private final String description;
        
        IncidentSeverity(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }

    public enum IncidentType {
        MALWARE("Malware"),
        RANSOMWARE("Ransomware"),
        PHISHING("Phishing"),
        DATA_BREACH("Data Breach"),
        UNAUTHORIZED_ACCESS("Unauthorized Access"),
        DOS_ATTACK("Denial of Service Attack"),
        INSIDER_THREAT("Insider Threat"),
        VULNERABILITY("Vulnerability"),
        COMPLIANCE_VIOLATION("Compliance Violation"),
        OTHER("Other");
        
        private final String description;
        
        IncidentType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
}