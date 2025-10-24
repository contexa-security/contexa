package io.contexa.contexaiam.resource;

import io.contexa.contexaiam.resource.enums.ConditionPattern;
import lombok.Data;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 메서드 분석 결과
 * SRP 준수: 분석 결과 정보만 담당
 */
@Data
public class MethodAnalysisResult {
    private String methodIdentifier;
    private String className;
    private String methodName;
    private Class<?> returnType;
    private List<ParameterInfo> parameters;
    private ConditionPattern detectedPattern;
    private List<String> generatedTemplates;
    private Map<String, Object> metadata;

    public MethodAnalysisResult() {
        this.parameters = new ArrayList<>();
        this.generatedTemplates = new ArrayList<>();
        this.metadata = new HashMap<>();
    }
} 