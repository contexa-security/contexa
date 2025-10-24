package io.contexa.contexaiam.resource.enums;

/**
 * 감지된 조건 패턴 타입
 * SRP 준수: 패턴 타입 정의만 담당
 */
public enum ConditionPattern {
    OBJECT_RETURN_PATTERN,    // hasPermission(#returnObject, permission)
    ID_PARAMETER_PATTERN,     // hasPermission(#id, #targetType, permission)
    OWNERSHIP_PATTERN,        // #returnObject.owner == #authentication.name
    UNIVERSAL_PATTERN,        // 범용 조건 (시간, IP 등)
    UNSUPPORTED_PATTERN       // 지원하지 않는 패턴
} 