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
package io.contexa.contexaiam.resource.service;

import io.contexa.contexaiam.domain.dto.ResourceManagementDto;
import io.contexa.contexaiam.domain.dto.ResourceMetadataDto;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Set;

public interface ResourceRegistryService {
    
    void refreshAndSynchronizeResources();

    Permission defineResourceAsPermission(Long resourceId, ResourceMetadataDto metadataDto);

    Page<ManagedResource> findResources(ResourceSearchCriteria searchCriteria, Pageable pageable);

    void updateResourceManagementStatus(Long resourceId, ResourceManagementDto managedDto); 

    void excludeResourceFromManagement(Long resourceId);

    Set<String> getAllServiceOwners();

    void batchUpdateStatus(List<Long> ids, ManagedResource.Status status);
}