package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;

@Entity
@Table(name = "PERMISSION")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Permission implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "permission_id")
    private Long id;

    @Column(name = "permission_name", unique = true, nullable = false)
    private String name;

    @Column(name = "friendly_name")
    private String friendlyName;

    @Column(name = "description", length = 1024)
    private String description;

    @Column(name = "target_type")
    private String targetType;

    @Column(name = "action_type")
    private String actionType;

    @Column(name = "condition_expression", length = 2048)
    private String conditionExpression;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "managed_resource_id", unique = true) // 외래 키 컬럼 지정
    private ManagedResource managedResource;

    /*@ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "PERMISSION_FUNCTIONS",
            joinColumns = @JoinColumn(name = "permission_id"),
            inverseJoinColumns = @JoinColumn(name = "function_catalog_id")
    )
    @Builder.Default
    private Set<FunctionCatalog> functions = new HashSet<>();*/
}