package io.contexa.contexaiam.admin.web.studio.service;

import io.contexa.contexaiam.admin.web.studio.dto.AccessPathDto;
import io.contexa.contexaiam.admin.web.studio.dto.EffectivePermissionDto;
import io.contexa.contexaiam.admin.support.visualization.dto.GraphDataDto; // 신규 import
// import io.contexa.contexaiam.studio.dto.*; // 패키지 존재하지 않음
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.VirtualSubject;

import java.util.List;
import java.util.Map;

/**
 * Authorization Studio의 'Canvas' 패널을 위한 시각화 데이터를 생성하고,
 * 복잡한 인가 관계를 분석하여 사용자가 쉽게 이해할 수 있도록 가공합니다.
 */
public interface StudioVisualizerService {

    /**
     * [기존 유지] "왜 이 사용자가 이 리소스에 접근할 수 있는가/없는가?"에 대한 답을 제공합니다.
     * 특정 주체와 리소스 간의 접근 경로를 추적하여 시각적인 텍스트 데이터로 반환합니다.
     * @param subjectId 분석할 주체(사용자/그룹)의 ID
     * @return 접근 경로의 각 단계를 담은 DTO
     */
    AccessPathDto analyzeAccessPath(Long subjectId, String subjectType, Long permissionId);

    /**
     * [신규 추가] 특정 주체와 권한 간의 접근 경로를 분석하여, UI에서 그래프로 렌더링할 수 있는 데이터 구조로 반환합니다.
     * @param subjectId 분석할 주체(사용자/그룹)의 ID
     * @param subjectType 주체의 타입 ("USER" 또는 "GROUP")
     * @param permissionId 분석할 권한의 ID
     * @return UI 그래프 라이브러리가 사용할 수 있는 노드 및 엣지 데이터 (GraphDataDto)
     */
    GraphDataDto analyzeAccessPathAsGraph(Long subjectId, String subjectType, Long permissionId);

    /**
     * [기존 유지] 특정 주체가 보유한 모든 유효 권한 목록을 반환합니다.
     * 각 권한이 어떤 역할, 그룹, 정책으로부터 부여되었는지 근거를 함께 제공합니다.
     * @param subjectId 분석할 주체(사용자/그룹)의 ID
     * @return 유효 권한 및 그 근거를 담은 DTO 목록
     */
    List<EffectivePermissionDto> getEffectivePermissionsForSubject(Long subjectId, String subjectType);

    /**
     * [신규 오버로딩 메서드]
     * DB에 저장되지 않은 가상의 주체에 대한 유효 권한을 계산합니다.
     * PermissionWizardService의 시뮬레이션 기능에 의해 호출됩니다.
     *
     * @param subject DB의 실제 정보에 UI의 변경사항이 메모리상에서만 적용된 가상 주체 객체
     * @return 계산된 유효 권한 및 그 근거를 담은 DTO 목록
     */
    List<EffectivePermissionDto> getEffectivePermissionsForSubject(VirtualSubject subject);

    /**
     * [신규] 특정 주체의 상세 정보(현재 할당된 내역, 유효 권한 목록)를 조회합니다.
     * 통합된 Studio의 인스펙터 '조회 모드'에서 사용됩니다.
     *
     * @param subjectId   분석할 주체(사용자/그룹)의 ID
     * @param subjectType 주체의 타입 ("USER" 또는 "GROUP")
     * @return 주체의 상세 정보를 담은 Map
     */
    Map<String, Object> getSubjectDetails(Long subjectId, String subjectType);

}