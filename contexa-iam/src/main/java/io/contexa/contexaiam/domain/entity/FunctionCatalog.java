package io.contexa.contexaiam.domain.entity;

import io.contexa.contexacommon.entity.ManagedResource;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "FUNCTION_CATALOG")
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class FunctionCatalog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "managed_resource_id", unique = true, nullable = false)
    private ManagedResource managedResource;

    @Column(nullable = false)
    private String friendlyName;

    @Column(length = 1024)
    private String description;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "function_group_id")
    private FunctionGroup functionGroup;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private CatalogStatus status = CatalogStatus.UNCONFIRMED;

    public enum CatalogStatus {
        UNCONFIRMED, 
        ACTIVE,      
        INACTIVE     
    }
}
