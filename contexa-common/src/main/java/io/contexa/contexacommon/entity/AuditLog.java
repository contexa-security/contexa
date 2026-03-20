package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_log")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class) 
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, updatable = false)
    @CreatedDate 
    private LocalDateTime timestamp;

    @Column(nullable = false)
    private String principalName; 

    @Column(nullable = false, length = 512)
    private String resourceIdentifier; 

    private String action; 

    @Column(nullable = false)
    private String decision; 

    @Column(length = 1024)
    private String reason; 

    private String outcome;

    @Column(length = 1024)
    private String resourceUri;

    private String clientIp;
    private String sessionId;

    @Column(columnDefinition = "TEXT")
    private String details;

    @Column(length = 50)
    private String eventCategory;

    @Column(length = 512)
    private String userAgent;

    @Column(length = 10)
    private String httpMethod;

    @Column(length = 2048)
    private String requestUri;

    private Double riskScore;

    @Column(length = 50)
    private String eventSource;

    @Column(length = 64)
    private String correlationId; 

    @PrePersist
    protected void onCreate() {
        if (this.timestamp == null) {
            this.timestamp = LocalDateTime.now();
        }
    }
}
