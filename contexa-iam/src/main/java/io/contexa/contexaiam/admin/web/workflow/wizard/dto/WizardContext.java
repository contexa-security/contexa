package io.contexa.contexaiam.admin.web.workflow.wizard.dto;

import lombok.Builder;

import java.io.Serializable;
import java.util.Set;

/**
 * [수정] 권한 부여 마법사의 세션 정보를 담는 DTO.
 * '리소스 워크벤치'에서 넘어온 권한 ID를 저장하기 위해 permissionIds 필드를 추가합니다.
 */
@Builder
public record WizardContext(
        String contextId,
        String sessionTitle,
        String sessionDescription,

        // 'Studio'에서 주체(사용자/그룹)를 관리하는 흐름에서 사용
        Subject targetSubject,
        Set<Long> initialAssignmentIds,

        Set<Long> permissionIds,

        // [신규] 일반적인 주체 선택을 위한 필드
        Set<Subject> subjects

) implements Serializable {

    private static final long serialVersionUID = 4L; // 버전 변경

    @Builder
    public record Subject(Long id, String type) implements Serializable {
        private static final long serialVersionUID = 1L;
    }
}