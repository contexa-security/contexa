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
package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.FunctionCatalog;
import io.contexa.contexacommon.entity.ManagedResource;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface FunctionCatalogRepository extends JpaRepository<FunctionCatalog, Long> {

    Optional<FunctionCatalog> findByManagedResource(ManagedResource managedResource);

    @Query("SELECT fc FROM FunctionCatalog fc " +
            "JOIN FETCH fc.managedResource " +
            "WHERE fc.status = :status " +
            "ORDER BY fc.id ASC")
    List<FunctionCatalog> findFunctionsByStatusWithDetails(@Param("status") FunctionCatalog.CatalogStatus status);

    @Query("SELECT fc FROM FunctionCatalog fc " +
            "JOIN FETCH fc.managedResource " +
            "LEFT JOIN FETCH fc.functionGroup " +
            "WHERE fc.status <> :status " +
            "ORDER BY fc.functionGroup.name, fc.friendlyName ASC")
    List<FunctionCatalog> findAllByStatusNotWithDetails(@Param("status") FunctionCatalog.CatalogStatus status);
    
    @Query("SELECT fc FROM FunctionCatalog fc " +
            "WHERE fc.status = 'ACTIVE'")
    List<FunctionCatalog> findAllActiveFunctions();

    @Query("SELECT fc FROM FunctionCatalog fc JOIN FETCH fc.managedResource LEFT JOIN FETCH fc.functionGroup")
    List<FunctionCatalog> findAllWithDetails();
}
