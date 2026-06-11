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

import io.contexa.contexacommon.entity.ManagedResource;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface ManagedResourceRepository extends JpaRepository<ManagedResource, Long>, ManagedResourceRepositoryCustom {

    Optional<ManagedResource> findByResourceIdentifier(String resourceIdentifier);

    List<ManagedResource> findByResourceType(ManagedResource.ResourceType resourceType);

    @Query("SELECT DISTINCT r.serviceOwner FROM ManagedResource r WHERE r.serviceOwner IS NOT NULL ORDER BY r.serviceOwner ASC")
    Set<String> findAllServiceOwners();

    @Query("SELECT r FROM ManagedResource r LEFT JOIN FETCH r.permission WHERE r.status IN :statuses")
    List<ManagedResource> findByStatusInWithPermission(List<ManagedResource.Status> statuses);

    @Query("SELECT r FROM ManagedResource r LEFT JOIN FETCH r.permission")
    List<ManagedResource> findAllWithPermission();

    long countByStatus(ManagedResource.Status status);

    @Query("SELECT m.status, COUNT(m) FROM ManagedResource m GROUP BY m.status")
    List<Object[]> countGroupByStatus();
}
