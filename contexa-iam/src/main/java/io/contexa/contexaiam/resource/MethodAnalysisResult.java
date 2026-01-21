package io.contexa.contexaiam.resource;

import io.contexa.contexaiam.resource.enums.ConditionPattern;
import lombok.Data;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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