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
package io.contexa.contexaiam.admin.web.metadata.service;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexaiam.domain.dto.FunctionCatalogDto;
import io.contexa.contexaiam.domain.dto.FunctionCatalogUpdateDto;
import io.contexa.contexaiam.domain.dto.GroupedFunctionCatalogDto;
import io.contexa.contexaiam.domain.entity.FunctionCatalog;
import io.contexa.contexaiam.domain.entity.FunctionGroup;
import io.contexa.contexaiam.repository.FunctionCatalogRepository;
import io.contexa.contexaiam.repository.FunctionGroupRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.modelmapper.ModelMapper;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("FunctionCatalogService")
class FunctionCatalogServiceTest {

    @Mock private FunctionCatalogRepository functionCatalogRepository;
    @Mock private FunctionGroupRepository functionGroupRepository;
    @Mock private ModelMapper modelMapper;

    @InjectMocks
    private FunctionCatalogService service;

    @Test
    @DisplayName("findUnconfirmedFunctions should return unconfirmed functions")
    void findUnconfirmedFunctions() {
        FunctionCatalog catalog = new FunctionCatalog();
        when(functionCatalogRepository.findFunctionsByStatusWithDetails(FunctionCatalog.CatalogStatus.UNCONFIRMED))
                .thenReturn(List.of(catalog));

        List<FunctionCatalog> result = service.findUnconfirmedFunctions();

        assertThat(result).containsExactly(catalog);
    }

    @Nested
    @DisplayName("getAllFunctionGroups")
    class GetGroups {
        @Test
        @DisplayName("should initialize default groups if empty")
        void empty() {
            when(functionGroupRepository.count()).thenReturn(0L);
            when(functionGroupRepository.findAll()).thenReturn(List.of(new FunctionGroup(), new FunctionGroup()));

            List<FunctionGroup> result = service.getAllFunctionGroups();

            verify(functionGroupRepository, times(2)).save(any());
            assertThat(result).hasSize(2);
        }

        @Test
        @DisplayName("should skip initialization if not empty")
        void notEmpty() {
            when(functionGroupRepository.count()).thenReturn(2L);
            when(functionGroupRepository.findAll()).thenReturn(List.of(new FunctionGroup(), new FunctionGroup()));

            List<FunctionGroup> result = service.getAllFunctionGroups();

            verify(functionGroupRepository, never()).save(any());
            assertThat(result).hasSize(2);
        }
    }

    @Nested
    @DisplayName("confirmFunction")
    class Confirm {
        @Test
        @DisplayName("should throw exception when catalog not found")
        void catalogNotFound() {
            when(functionCatalogRepository.findById(1L)).thenReturn(Optional.empty());

            assertThrows(IllegalArgumentException.class, () -> service.confirmFunction(1L, 10L));
        }

        @Test
        @DisplayName("should throw exception when group not found")
        void groupNotFound() {
            when(functionCatalogRepository.findById(1L)).thenReturn(Optional.of(new FunctionCatalog()));
            when(functionGroupRepository.findById(10L)).thenReturn(Optional.empty());

            assertThrows(IllegalArgumentException.class, () -> service.confirmFunction(1L, 10L));
        }

        @Test
        @DisplayName("should update status to ACTIVE and save")
        void success() {
            FunctionCatalog catalog = new FunctionCatalog();
            FunctionGroup group = new FunctionGroup();

            when(functionCatalogRepository.findById(1L)).thenReturn(Optional.of(catalog));
            when(functionGroupRepository.findById(10L)).thenReturn(Optional.of(group));

            service.confirmFunction(1L, 10L);

            assertThat(catalog.getStatus()).isEqualTo(FunctionCatalog.CatalogStatus.ACTIVE);
            assertThat(catalog.getFunctionGroup()).isEqualTo(group);
            verify(functionCatalogRepository).save(catalog);
        }
    }

    @Test
    @DisplayName("getManageableCatalogs should map non-unconfirmed catalogs to DTOs")
    void getManageableCatalogs() {
        FunctionCatalog catalog = new FunctionCatalog();
        catalog.setId(5L);
        catalog.setStatus(FunctionCatalog.CatalogStatus.ACTIVE);
        when(functionCatalogRepository.findAllByStatusNotWithDetails(FunctionCatalog.CatalogStatus.UNCONFIRMED))
                .thenReturn(List.of(catalog));

        List<FunctionCatalogDto> result = service.getManageableCatalogs();

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getId()).isEqualTo(5L);
    }

    @Nested
    @DisplayName("updateCatalog")
    class UpdateCatalog {
        @Test
        @DisplayName("should modify fields and save")
        void success() {
            FunctionCatalog catalog = new FunctionCatalog();
            FunctionGroup group = new FunctionGroup();
            when(functionCatalogRepository.findById(1L)).thenReturn(Optional.of(catalog));
            when(functionGroupRepository.findById(10L)).thenReturn(Optional.of(group));

            FunctionCatalogUpdateDto dto = new FunctionCatalogUpdateDto();
            dto.setGroupId(10L);
            dto.setFriendlyName("FN");
            dto.setDescription("DESC");
            dto.setStatus(FunctionCatalog.CatalogStatus.INACTIVE);

            service.updateCatalog(1L, dto);

            assertThat(catalog.getFriendlyName()).isEqualTo("FN");
            assertThat(catalog.getDescription()).isEqualTo("DESC");
            assertThat(catalog.getStatus()).isEqualTo(FunctionCatalog.CatalogStatus.INACTIVE);
            assertThat(catalog.getFunctionGroup()).isEqualTo(group);
            verify(functionCatalogRepository).save(catalog);
        }
    }

    @Test
    @DisplayName("updateSingleStatus should update and save catalog status")
    void updateSingleStatus() {
        FunctionCatalog catalog = new FunctionCatalog();
        when(functionCatalogRepository.findById(1L)).thenReturn(Optional.of(catalog));

        service.updateSingleStatus(1L, "inactive");

        assertThat(catalog.getStatus()).isEqualTo(FunctionCatalog.CatalogStatus.INACTIVE);
        verify(functionCatalogRepository).save(catalog);
    }

    @Test
    @DisplayName("getGroupedCatalogs should group catalogs by status")
    void getGroupedCatalogs() {
        FunctionCatalog c1 = new FunctionCatalog();
        c1.setStatus(FunctionCatalog.CatalogStatus.ACTIVE);
        FunctionCatalog c2 = new FunctionCatalog();
        c2.setStatus(FunctionCatalog.CatalogStatus.UNCONFIRMED);

        when(functionCatalogRepository.findAllWithDetails()).thenReturn(List.of(c1, c2));

        GroupedFunctionCatalogDto result = service.getGroupedCatalogs();

        assertThat(result.getActive()).hasSize(1);
        assertThat(result.getUnconfirmed()).hasSize(1);
    }

    @Test
    @DisplayName("confirmBatch should invoke confirmFunction for payload items")
    void confirmBatch() {
        FunctionCatalog catalog = new FunctionCatalog();
        FunctionGroup group = new FunctionGroup();
        when(functionCatalogRepository.findById(1L)).thenReturn(Optional.of(catalog));
        when(functionGroupRepository.findById(10L)).thenReturn(Optional.of(group));

        service.confirmBatch(List.of(Map.of("catalogId", 1L, "groupId", 10L)));

        verify(functionCatalogRepository).save(catalog);
    }

    @Test
    @DisplayName("batchUpdateStatus should update status for list of catalog IDs")
    void batchUpdateStatus() {
        FunctionCatalog c1 = new FunctionCatalog();
        FunctionCatalog c2 = new FunctionCatalog();
        when(functionCatalogRepository.findAllById(List.of(1L, 2L))).thenReturn(List.of(c1, c2));

        service.batchUpdateStatus(List.of(1L, 2L), "inactive");

        assertThat(c1.getStatus()).isEqualTo(FunctionCatalog.CatalogStatus.INACTIVE);
        assertThat(c2.getStatus()).isEqualTo(FunctionCatalog.CatalogStatus.INACTIVE);
        verify(functionCatalogRepository).saveAll(any());
    }
}
