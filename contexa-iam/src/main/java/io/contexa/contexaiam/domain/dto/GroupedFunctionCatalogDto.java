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
package io.contexa.contexaiam.domain.dto;

import io.contexa.contexaiam.domain.entity.FunctionCatalog;
import lombok.Getter;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Getter
public class GroupedFunctionCatalogDto {

    private final List<FunctionCatalogDto> unconfirmed;
    private final List<FunctionCatalogDto> active;
    private final List<FunctionCatalogDto> inactive;

    public GroupedFunctionCatalogDto(Map<FunctionCatalog.CatalogStatus, List<FunctionCatalogDto>> groupedCatalogs) {
        this.unconfirmed = groupedCatalogs.getOrDefault(FunctionCatalog.CatalogStatus.UNCONFIRMED, Collections.emptyList());
        this.active = groupedCatalogs.getOrDefault(FunctionCatalog.CatalogStatus.ACTIVE, Collections.emptyList());
        this.inactive = groupedCatalogs.getOrDefault(FunctionCatalog.CatalogStatus.INACTIVE, Collections.emptyList());
    }
}
