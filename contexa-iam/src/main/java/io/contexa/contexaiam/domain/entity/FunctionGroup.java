package io.contexa.contexaiam.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "FUNCTION_GROUP")
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class FunctionGroup {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String name;

    @OneToMany(mappedBy = "functionGroup")
    @Builder.Default
    private Set<FunctionCatalog> functions = new HashSet<>();
}