package io.contexa.contexaiam.admin.web.studio.dto;

import io.contexa.contexaiam.domain.dto.PolicyDto;

/**
 * 정책 시뮬레이션 실행을 요청하기 위한 DTO 입니다.
 */
public record SimulationRequestDto(
        ActionType actionType,
        PolicyDto policyDraft // 생성, 수정, 삭제 대상이 되는 정책의 데이터
) {
    public enum ActionType {
        CREATE,
        UPDATE,
        DELETE
    }
}