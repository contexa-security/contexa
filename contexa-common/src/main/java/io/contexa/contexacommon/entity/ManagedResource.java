package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "MANAGED_RESOURCE")
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class ManagedResource {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, length = 512)
    private String resourceIdentifier;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ResourceType resourceType;
    @Enumerated(EnumType.STRING)
    private HttpMethod httpMethod;
    @Column(nullable = false)
    private String friendlyName;
    @Column(length = 1024)
    private String description;
    private String serviceOwner;
    private String parameterTypes;
    private String returnType;
    private String apiDocsUrl;
    private String sourceCodeLocation;
    @Column(length = 1024)
    private String availableContextVariables;

    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private Status status = Status.NEEDS_DEFINITION;

    @OneToOne(mappedBy = "managedResource", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    private Permission permission;

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(nullable = false)
    private LocalDateTime updatedAt;

    public enum ResourceType { URL, METHOD }
    public enum HttpMethod { GET, POST, PUT, DELETE, PATCH, ANY }
    public enum Status {
        NEEDS_DEFINITION, 
        PERMISSION_CREATED, 
        POLICY_CONNECTED, 
        EXCLUDED 
    }
}