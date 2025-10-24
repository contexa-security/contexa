package io.contexa.contexaiam.domain.dto;

import java.util.List;
import java.util.Map;

// 권한 현황 조회를 위한 DTO
public record EntitlementDto(
        Long policyId,
        String subjectName,      // "관리자 그룹", "사용자 김씨"
        String subjectType,      // "GROUP", "USER"
        String resourceName,     // "사용자 정보 수정"
        List<String> actions,    // ["쓰기", "삭제"]
        List<String> conditions  // ["사내 IP 에서만"]
) {}

