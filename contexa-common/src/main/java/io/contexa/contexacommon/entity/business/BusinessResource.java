package io.contexa.contexacommon.entity.business;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * 일반 사용자가 인가 정책을 설정할 때 사용하는 비즈니스 자원을 정의하는 엔티티.
 * (예: '재무 보고서', '인사 평가 자료' 등)
 */
@Entity
@Table(name = "BUSINESS_RESOURCE")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BusinessResource implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String name; // 사용자에게 표시될 자원 이름 (예: 재무 보고서)

    @Column(nullable = false)
    private String resourceType; // Permission의 targetType과 매핑될 기술적 타입 (예: FINANCIAL_REPORT)

    @Column(length = 1024)
    private String description;

    @OneToMany(mappedBy = "businessResource", fetch = FetchType.LAZY)
    private Set<BusinessResourceAction> availableActions = new HashSet<>();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof BusinessResource that)) return false;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
