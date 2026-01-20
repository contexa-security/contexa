package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
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
    private String status; 
    private String parameters; 

    @Column(columnDefinition = "TEXT")
    private String details; 

    @PrePersist
    protected void onCreate() {
        if (this.timestamp == null) {
            this.timestamp = LocalDateTime.now();
        }
    }
}
