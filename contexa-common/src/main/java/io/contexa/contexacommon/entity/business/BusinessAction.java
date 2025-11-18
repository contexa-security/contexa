package io.contexa.contexacommon.entity.business;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity
@Table(name = "BUSINESS_ACTION")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BusinessAction implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String name; // 사용자에게 표시될 행위 이름 (예: 조회하기)

    @Column(nullable = false)
    private String actionType; // Permission의 actionType과 매핑될 기술적 타입 (예: READ)

    @Column(length = 1024)
    private String description;

    @OneToMany(mappedBy = "businessAction")
    @Builder.Default
    private Set<BusinessResourceAction> resources = new HashSet<>();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof BusinessAction that)) return false;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}