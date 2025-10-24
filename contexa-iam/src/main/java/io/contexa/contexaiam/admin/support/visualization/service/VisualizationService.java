package io.contexa.contexaiam.admin.support.visualization.service;

import io.contexa.contexaiam.admin.support.visualization.dto.GraphDataDto;

public interface VisualizationService {
    /**
     * 특정 주체(사용자)의 권한 상속 관계를 그래프 데이터로 생성합니다.
     * @param userId 분석할 사용자의 ID
     * @return UI에서 그래프로 렌더링할 수 있는 노드 및 엣지 데이터
     */
    GraphDataDto generatePermissionGraphForUser(Long userId);
}
