package io.contexa.contexaiam.admin.web.metadata.service;

import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;

import java.util.List;

/**
 * [신규] 권한 카탈로그 서비스
 * 시스템의 모든 비즈니스 권한(Permission)을 카탈로그 형태로 관리합니다.
 * Resource 스캔 결과를 바탕으로 Permission을 자동 생성/업데이트하고,
 * 정책 생성 UI(마법사, Studio)에 사용될 권한 목록을 제공하는 핵심적인 역할을 합니다.
 */
public interface PermissionCatalogService {

    /**
     * [기존 synchronize 역할 대체 및 구체화]
     * 단일 ManagedResource를 기반으로 Permission을 생성하거나 업데이트합니다.
     * '리소스 워크벤치'에서 권한을 정의할 때 ResourceRegistryService에 의해 호출됩니다.
     *
     * @param definedResource is_defined=true로 설정된, 비즈니스 의미가 부여된 리소스
     * @return 생성 또는 업데이트된 Permission
     */
    Permission synchronizePermissionFor(ManagedResource definedResource);

    /**
     * [기존 getAvailablePermissions 역할 유지]
     * 권한 부여 마법사 등에서 사용할 수 있는, 현재 시스템에 정의된 모든 권한 목록을 조회합니다.
     * @return 사용 가능한 Permission DTO 목록
     */
    List<PermissionDto> getAvailablePermissions();
}