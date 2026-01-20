package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.repository.FunctionCatalogRepository;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
public class PermissionServiceImpl implements PermissionService {
    private final PermissionRepository permissionRepository;
    private final FunctionCatalogRepository functionCatalogRepository;

    
    @Transactional
    @Caching(
            evict = {@CacheEvict(value = "usersWithRolesAndPermissions", allEntries = true)}, 
            put = {@CachePut(value = "permissions", key = "#result.id")} 
    )
    @Override
    public Permission createPermission(Permission permission) {
        
        if (permissionRepository.findByName(permission.getName()).isPresent()) {
            throw new IllegalArgumentException("Permission with name " + permission.getName() + " already exists.");
        }
        return permissionRepository.save(permission);
    }

    
    @Cacheable(value = "permissions", key = "#id")
    @Override
    public Optional<Permission> getPermission(Long id) {
        return permissionRepository.findById(id);
    }

    
    @Cacheable(value = "permissions", key = "'allPermissions'")
    @Override
    public List<Permission> getAllPermissions() {
        return permissionRepository.findAll();
    }

    
    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithRolesAndPermissions", allEntries = true), 
                    @CacheEvict(value = "permissions", key = "#id"), 
                    @CacheEvict(value = "permissions", key = "'allPermissions'") 
            }
    )
    @Override
    public void deletePermission(Long id) {
        permissionRepository.deleteById(id);
    }

    
    @Caching(
            evict = {@CacheEvict(value = "usersWithRolesAndPermissions", allEntries = true)}, 
            put = {@CachePut(value = "permissions", key = "#result.id")} 
    )
    @Transactional
    @Override
    public Permission updatePermission(Long id, PermissionDto permissionDto) {
        Permission permission = permissionRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Permission not found: " + id));

        permission.setName(permissionDto.getName());
        permission.setFriendlyName(permissionDto.getFriendlyName());
        permission.setDescription(permissionDto.getDescription());
        permission.setTargetType(permissionDto.getTargetType());
        permission.setActionType(permissionDto.getActionType());
        permission.setConditionExpression(permissionDto.getConditionExpression());

        return permissionRepository.save(permission);
    }

    
    @Cacheable(value = "permissionsByName", key = "#name")
    @Override
    public Optional<Permission> findByName(String name) {
        return permissionRepository.findByName(name);
    }
}