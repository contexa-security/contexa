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
