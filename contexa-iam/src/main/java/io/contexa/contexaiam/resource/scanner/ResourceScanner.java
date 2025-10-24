package io.contexa.contexaiam.resource.scanner;

import io.contexa.contexacommon.entity.ManagedResource;

import java.util.List;

/**
 * 애플리케이션 내의 보호 가능한 모든 리소스(URL, Method 등)를
 * 식별하고 등록하는 책임을 갖는 컴포넌트입니다.
 */
public interface ResourceScanner {
    /**
     * 애플리케이션 컨텍스트를 스캔하여 관리 가능한 리소스 목록을 반환합니다.
     * @return 탐지된 리소스 정보(ManagedResource) 목록
     */
    List<ManagedResource> scan();
}