package io.contexa.contexacommon.entity.business;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;


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

    @Column(unique = true, nullable = false, length = 255)
    private String name;

    @Column(nullable = false, length = 100)
    private String resourceType;

    @Column(length = 1024)
    private String description;

    @OneToMany(mappedBy = "businessResource", fetch = FetchType.LAZY)
    @Builder.Default
    @JsonIgnore
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
