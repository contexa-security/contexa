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
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Thin caching layer around AdminMenuRepository.findAllWithRolesOrderByMenuOrder.
 * AdminMenuService cannot annotate its own methods with @Cacheable because Spring
 * AOP proxies would skip self-invocation. This bean sits between the service and
 * the repository so the sidebar render path triggers the underlying join query
 * only once per process window.
 */
public class AdminMenuQueryCache {

    static final String CACHE_NAME = "adminMenuAllWithRoles";
    static final String CACHE_KEY = "'all-with-roles'";

    private final AdminMenuRepository repository;

    public AdminMenuQueryCache(AdminMenuRepository repository) {
        this.repository = repository;
    }

    @Cacheable(cacheNames = CACHE_NAME, key = CACHE_KEY)
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<AdminMenu> findAllWithRoles() {
        return repository.findAllWithRolesOrderByMenuOrder();
    }

    @CacheEvict(cacheNames = CACHE_NAME, allEntries = true)
    public void invalidate() {
        // Annotation alone clears the cache.
    }
}
