package io.contexa.contexacore.domain.entity;

import io.contexa.contexacore.domain.IncidentHistoryLog;
import io.contexa.contexacore.domain.SoarIncidentStatus;
import io.contexa.contexacore.utils.JpaListConverter;
import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "soar_incidents")
@EntityListeners(AuditingEntityListener.class)
public class SoarIncident {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String title;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SoarIncidentStatus status;

    @Column
    private String severity;

    @Column
    private String incidentId;

    @Column
    private String type;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(columnDefinition = "TEXT")
    private String metadata;

    @Convert(converter = JpaListConverter.class)
    @Lob
    @Column(columnDefinition = "TEXT")
    private List<IncidentHistoryLog> history = new ArrayList<>();

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(nullable = false)
    private LocalDateTime updatedAt;

    public void addHistoryLog(String log) {
        if (this.history == null) {
            this.history = new ArrayList<>();
        }
        this.history.add(new IncidentHistoryLog(LocalDateTime.now(), log));
    }

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public SoarIncidentStatus getStatus() { return status; }
    public void setStatus(SoarIncidentStatus status) { this.status = status; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getMetadata() { return metadata; }
    public void setMetadata(String metadata) { this.metadata = metadata; }
    public void setMetadata(java.util.Map<String, Object> metadataMap) {
        if (metadataMap != null) {
            try {
                com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                this.metadata = mapper.writeValueAsString(metadataMap);
            } catch (Exception e) {
                this.metadata = metadataMap.toString();
            }
        }
    }
    
    public List<IncidentHistoryLog> getHistory() { return history; }
    public void setHistory(List<IncidentHistoryLog> history) { this.history = history; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
}