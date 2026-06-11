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
package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.business.BusinessResource;
import io.contexa.contexacommon.entity.business.BusinessResourceAction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;


@Repository
public interface BusinessResourceActionRepository extends JpaRepository<BusinessResourceAction, BusinessResourceAction.BusinessResourceActionId> {
    
    
    @Query("SELECT bra.businessResource FROM BusinessResourceAction bra WHERE bra.businessResource.name = :resourceId")
    Optional<BusinessResource> findByResourceIdentifier(@Param("resourceId") String resourceId);
    
    
    @Query("SELECT 10.5 FROM BusinessResourceAction bra WHERE bra.businessResource.name = :resourceId")
    double getAverageAccessesPerDay(@Param("resourceId") String resourceId);
    
    
    @Query("SELECT br.resourceType FROM BusinessResource br WHERE br.name = :resourceId")
    Optional<String> getResourceSensitivityLevel(@Param("resourceId") String resourceId);
    
    
    @Query("SELECT COUNT(bra) FROM BusinessResourceAction bra WHERE bra.businessResource.name = :resourceId")
    long countActionsByResourceIdentifier(@Param("resourceId") String resourceId);
}
