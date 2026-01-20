package io.contexa.contexaiam.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "ROLE_HIERARCHY_CONFIG") 
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

    
    @Column(name = "hierarchy_string", columnDefinition = "TEXT", nullable = false, unique = true)
    private String hierarchyString;

    @Column(name = "description")
    private String description;

    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private Boolean isActive = false; 

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