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

    /**
     * [신규/대체] 리소스의 현재 상태를 나타내는 Enum.
     * boolean 필드보다 더 명확한 상태 관리를 제공합니다.
     */
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
        NEEDS_DEFINITION, // 정의 필요 (스캔 후 초기 상태)
        PERMISSION_CREATED, // 권한 생성됨 (정책과는 아직 미연결)
        POLICY_CONNECTED, // 정책 연결됨
        EXCLUDED // 관리 제외
    }
}