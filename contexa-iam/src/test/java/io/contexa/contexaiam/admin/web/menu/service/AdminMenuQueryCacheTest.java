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
package io.contexa.contexaiam.admin.web.menu.service;

import io.contexa.contexacommon.entity.AdminMenu;
import io.contexa.contexacommon.repository.AdminMenuRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AdminMenuQueryCache")
class AdminMenuQueryCacheTest {

    @Mock
    private AdminMenuRepository repository;

    @InjectMocks
    private AdminMenuQueryCache queryCache;

    @Test
    @DisplayName("findAllWithRoles should delegate to repository")
    void findAllWithRoles() {
        AdminMenu menu = AdminMenu.builder().id(1L).name("Menu").build();
        when(repository.findAllWithRolesOrderByMenuOrder()).thenReturn(List.of(menu));

        List<AdminMenu> result = queryCache.findAllWithRoles();

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getName()).isEqualTo("Menu");
        verify(repository, times(1)).findAllWithRolesOrderByMenuOrder();
    }

    @Test
    @DisplayName("invalidate should run without exceptions")
    void invalidate() {
        // Since caching is handled by Spring AOP, unit test just verifies method execution
        queryCache.invalidate();
    }
}
