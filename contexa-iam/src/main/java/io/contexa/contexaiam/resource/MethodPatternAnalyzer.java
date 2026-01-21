package io.contexa.contexaiam.resource;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class MethodPatternAnalyzer {

    @Data
    public static class MethodAnalysisResult {
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

    @Data
    public static class ParameterInfo {
        private String name;
        private Class<?> type;
        private int index;
        private boolean isIdType;
        private boolean isEntityType;
    }

    public enum ConditionPattern {
        OBJECT_RETURN_PATTERN,    
        ID_PARAMETER_PATTERN,     
        OWNERSHIP_PATTERN,        
        UNIVERSAL_PATTERN,        
        UNSUPPORTED_PATTERN       
    }

    public MethodAnalysisResult analyzeMethod(Method method, String resourceIdentifier) {
                
        MethodAnalysisResult result = new MethodAnalysisResult();
        result.setMethodIdentifier(generateMethodIdentifier(method, resourceIdentifier));
        result.setClassName(method.getDeclaringClass().getSimpleName());
        result.setMethodName(method.getName());
        result.setReturnType(method.getReturnType());

        analyzeParameters(method, result);

        detectConditionPattern(result);

        generateTemplates(result);

        return result;
    }

    private void analyzeParameters(Method method, MethodAnalysisResult result) {
        Parameter[] parameters = method.getParameters();
        
        for (int i = 0; i < parameters.length; i++) {
            Parameter param = parameters[i];
            ParameterInfo paramInfo = new ParameterInfo();
            
            paramInfo.setName(param.getName());
            paramInfo.setType(param.getType());
            paramInfo.setIndex(i);
            paramInfo.setIdType(isIdType(param.getType()));
            paramInfo.setEntityType(isEntityType(param.getType()));
            
            result.getParameters().add(paramInfo);
        }
    }

    private void detectConditionPattern(MethodAnalysisResult result) {
        
        if (isEntityReturnType(result.getReturnType())) {
            result.setDetectedPattern(ConditionPattern.OBJECT_RETURN_PATTERN);
            result.getMetadata().put("canUseReturnObject", true);
            return;
        }

        Optional<ParameterInfo> idParam = result.getParameters().stream()
            .filter(ParameterInfo::isIdType)
            .findFirst();
            
        if (idParam.isPresent()) {
            result.setDetectedPattern(ConditionPattern.ID_PARAMETER_PATTERN);
            result.getMetadata().put("idParameterIndex", idParam.get().getIndex());
            result.getMetadata().put("idParameterName", idParam.get().getName());

            String entityType = inferEntityTypeFromMethod(result);
            result.getMetadata().put("entityType", entityType);
            return;
        }

        result.setDetectedPattern(ConditionPattern.UNIVERSAL_PATTERN);
    }

    private void generateTemplates(MethodAnalysisResult result) {
        switch (result.getDetectedPattern()) {
            case OBJECT_RETURN_PATTERN:
                generateObjectReturnTemplates(result);
                break;
            case ID_PARAMETER_PATTERN:
                generateIdParameterTemplates(result);
                break;
            case UNIVERSAL_PATTERN:
                generateUniversalTemplates(result);
                break;
            default:
                log.warn("지원하지 않는 패턴: {}", result.getDetectedPattern());
        }
    }

    private void generateObjectReturnTemplates(MethodAnalysisResult result) {
        String entityType = result.getReturnType().getSimpleName();

        result.getGeneratedTemplates().add("hasPermission(#returnObject, 'READ')");
        result.getGeneratedTemplates().add("hasPermission(#returnObject, 'UPDATE')");
        result.getGeneratedTemplates().add("hasPermission(#returnObject, 'DELETE')");

        result.getGeneratedTemplates().add("#returnObject.owner == #authentication.name");
        result.getGeneratedTemplates().add("#returnObject.createdBy == #authentication.name");
        
        result.getMetadata().put("templateType", "object_return");
        result.getMetadata().put("entityType", entityType);
    }

    private void generateIdParameterTemplates(MethodAnalysisResult result) {
        String entityType = (String) result.getMetadata().get("entityType");
        String idParamName = (String) result.getMetadata().get("idParameterName");

        result.getGeneratedTemplates().add(String.format("hasPermission(#%s, '%s', 'UPDATE')", idParamName, entityType));
        result.getGeneratedTemplates().add(String.format("hasPermission(#%s, '%s', 'DELETE')", idParamName, entityType));

        if ("User".equals(entityType)) {
            result.getGeneratedTemplates().add(String.format("#%s == #authentication.id", idParamName));
        }
        
        result.getMetadata().put("templateType", "id_parameter");
        result.getMetadata().put("entityType", entityType);
    }

    private void generateUniversalTemplates(MethodAnalysisResult result) {
        
        result.getGeneratedTemplates().add("T(java.time.LocalTime).now().hour >= 9 and T(java.time.LocalTime).now().hour <= 18");
        result.getGeneratedTemplates().add("T(java.time.LocalDate).now().dayOfWeek.value <= 5");

        result.getGeneratedTemplates().add("#request.remoteAddr matches '^192\\\\.168\\\\..*'");
        result.getGeneratedTemplates().add("#request.remoteAddr matches '^10\\\\..*'");

        result.getGeneratedTemplates().add("hasRole('ADMIN')");
        result.getGeneratedTemplates().add("hasRole('MANAGER')");
        result.getGeneratedTemplates().add("hasAuthority('SYSTEM_ADMIN')");
        
        result.getMetadata().put("templateType", "universal");
    }

    private String generateMethodIdentifier(Method method, String resourceIdentifier) {
        return String.format("%s_%s_%s", 
            resourceIdentifier,
            method.getDeclaringClass().getSimpleName(),
            method.getName());
    }

    private boolean isIdType(Class<?> type) {
        return type == Long.class || type == long.class ||
               type == Integer.class || type == int.class ||
               type == String.class;
    }

    private boolean isEntityType(Class<?> type) {
        
        return type.getPackage() != null && 
               type.getPackage().getName().contains(".entity");
    }

    private boolean isEntityReturnType(Class<?> returnType) {
        return !returnType.equals(void.class) && 
               !returnType.equals(Void.class) &&
               !returnType.isPrimitive() &&
               !returnType.equals(String.class) &&
               isEntityType(returnType);
    }

    private String inferEntityTypeFromMethod(MethodAnalysisResult result) {
        String methodName = result.getMethodName();

        if (methodName.contains("User")) return "User";
        if (methodName.contains("Project")) return "Project";
        if (methodName.contains("Document")) return "Document";
        if (methodName.contains("Role")) return "Role";
        if (methodName.contains("Permission")) return "Permission";

        String className = result.getClassName();
        if (className.endsWith("Controller")) {
            String entityName = className.replace("Controller", "");
            return entityName;
        }

        return "Entity";
    }

    public List<MethodAnalysisResult> analyzeMethods(List<Method> methods, String resourceIdentifier) {
                
        List<MethodAnalysisResult> results = methods.stream()
            .map(method -> analyzeMethod(method, resourceIdentifier))
            .collect(Collectors.toList());
        
                return results;
    }
} 