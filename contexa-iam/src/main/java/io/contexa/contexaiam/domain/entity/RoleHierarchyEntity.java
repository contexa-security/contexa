package io.contexa.contexaiam.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "ROLE_HIERARCHY_CONFIG") // 'ROLE_HIERARCHY'는 예약어일 수 있어 'ROLE_HIERARCHY_CONFIG'로 명명
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RoleHierarchyEntity implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "hierarchy_id")
    private Long id;

    // 역할 계층 관계를 정의하는 문자열 (예: "ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER")
    @Column(name = "hierarchy_string", columnDefinition = "TEXT", nullable = false, unique = true)
    private String hierarchyString;

    @Column(name = "description")
    private String description;

    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private Boolean isActive = false; // 현재 활성화된 계층 설정인지 여부

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RoleHierarchyEntity that = (RoleHierarchyEntity) o;
        return Objects.equals(hierarchyString, that.hierarchyString);
    }

    @Override
    public int hashCode() {
        return Objects.hash(hierarchyString);
    }
}