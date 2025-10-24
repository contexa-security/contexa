package io.contexa.contexaiam.security.xacml.pap.dto;

import java.util.Set;

/**
 * 적절한 정책 템플릿을 추천하기 위해 사용되는 컨텍스트 DTO 입니다.
 */
public record PolicyContext(
        String userDepartment,
        Set<String> userRoles
) {}
