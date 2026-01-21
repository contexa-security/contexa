package io.contexa.contexaiam.resource;

import lombok.Data;

@Data
public class ParameterInfo {
    private String name;
    private Class<?> type;
    private int index;
    private boolean isIdType;
    private boolean isEntityType;
} 