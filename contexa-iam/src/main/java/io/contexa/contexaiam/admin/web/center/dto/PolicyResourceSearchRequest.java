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
package io.contexa.contexaiam.admin.web.center.dto;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import lombok.Data;

import java.util.Locale;

@Data
public class PolicyResourceSearchRequest {
    private String keyword;
    private String resourceType;
    private String serviceOwner;
    private String status;

    public ResourceSearchCriteria toCriteria() {
        ResourceSearchCriteria criteria = new ResourceSearchCriteria();
        criteria.setKeyword(keyword);
        criteria.setResourceType(enumValue(ManagedResource.ResourceType.class, resourceType));
        criteria.setServiceOwner(serviceOwner);
        criteria.setStatus(enumValue(ManagedResource.Status.class, status));
        return criteria;
    }

    private static <E extends Enum<E>> E enumValue(Class<E> enumType, String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return Enum.valueOf(enumType, value.trim().toUpperCase(Locale.ROOT));
    }
}
