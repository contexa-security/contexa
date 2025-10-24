package io.contexa.contexaiam.security.xacml.pap.dto;

import java.util.Map;
import java.util.Set;

/**
 * 정책 시뮬레이션을 위한 컨텍스트(입력값) DTO 입니다.
 */
public record SimulationContext(
        Set<Long> userIds, // 이 사용자들이
        Set<Long> permissionIds, // 이 권한들에 대해
        Map<String, Object> environmentAttributes // 이런 환경(IP, 시간 등)에서 접근 시
) {}
