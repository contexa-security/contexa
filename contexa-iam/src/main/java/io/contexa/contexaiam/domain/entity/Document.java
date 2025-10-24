package io.contexa.contexaiam.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Objects;

@Entity
@Table(name = "DOCUMENT") // 테이블 이름은 'DOCUMENT'
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Document implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "document_id")
    private Long id;

    @Column(name = "title", nullable = false)
    private String title;

    @Column(name = "content", columnDefinition = "TEXT") // 긴 텍스트를 위해 TEXT 타입
    private String content;

    @Column(name = "owner_username", nullable = false) // 문서 소유자 (Users.username과 매핑)
    private String ownerUsername;

    @Column(name = "created_at", nullable = false)
    @Temporal(TemporalType.TIMESTAMP)
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at")
    @Temporal(TemporalType.TIMESTAMP)
    private LocalDateTime updatedAt;

    @PrePersist // 엔티티 저장 전 호출
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    @PreUpdate // 엔티티 업데이트 전 호출
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Document document = (Document) o;
        return id != null && Objects.equals(id, document.id); // ID 기반 동등성 (영속성 컨텍스트 고려)
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
