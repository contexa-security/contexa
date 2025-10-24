package io.contexa.contexaiam.admin.web.studio.service;

import io.contexa.contexaiam.admin.web.studio.dto.ExplorerItemDto;
import java.util.List;
import java.util.Map;

/**
 * [수정] Authorization Studio의 'Explorer' 패널에 필요한 모든 데이터 목록을
 * 단일 API 호출로 제공합니다.
 */
public interface StudioExplorerService {
    /**
     * Explorer에 표시될 모든 아이템(주체, 권한, 정책)을 타입별로 그룹화하여 반환합니다.
     * @return 타입(users, groups, permissions, policies)을 키로 가지는 데이터 맵
     */
    Map<String, List<ExplorerItemDto>> getExplorerItems();
}