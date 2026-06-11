/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
