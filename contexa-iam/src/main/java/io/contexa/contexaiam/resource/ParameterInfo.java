package io.contexa.contexaiam.resource;

import lombok.Data;

/**
 * 파라미터 정보
 * SRP 준수: 파라미터 정보만 담당
 */
@Data
public class ParameterInfo {
    private String name;
    private Class<?> type;
    private int index;
    private boolean isIdType;
    private boolean isEntityType;
} 