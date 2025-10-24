package io.contexa.contexaiam.admin.web.studio.dto;

import java.util.List;

/**
 * 특정 주체와 리소스 간의 접근 경로 분석 결과를 담는 DTO 입니다.
 */
public record AccessPathDto(
        List<AccessPathNode> nodes,
        boolean accessGranted,
        String finalReason
) {}