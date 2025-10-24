package io.contexa.contexaiam.resource;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Slf4j
public class MethodPatternAnalyzer {

    /**
     * 메서드 분석 결과를 담는 DTO
     */
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

    /**
     * 파라미터 정보를 담는 DTO
     */
    @Data
    public static class ParameterInfo {
        private String name;
        private Class<?> type;
        private int index;
        private boolean isIdType;
        private boolean isEntityType;
    }

    /**
     * 감지된 조건 패턴 타입
     */
    public enum ConditionPattern {
        OBJECT_RETURN_PATTERN,    // hasPermission(#returnObject, permission)
        ID_PARAMETER_PATTERN,     // hasPermission(#id, #targetType, permission)
        OWNERSHIP_PATTERN,        // #returnObject.owner == #authentication.name
        UNIVERSAL_PATTERN,        // 범용 조건 (시간, IP 등)
        UNSUPPORTED_PATTERN       // 지원하지 않는 패턴
    }

    /**
     * 메서드를 분석하여 적용 가능한 조건 패턴을 감지합니다.
     */
    public MethodAnalysisResult analyzeMethod(Method method, String resourceIdentifier) {
        log.debug("메서드 분석 시작: {}.{}", method.getDeclaringClass().getSimpleName(), method.getName());
        
        MethodAnalysisResult result = new MethodAnalysisResult();
        result.setMethodIdentifier(generateMethodIdentifier(method, resourceIdentifier));
        result.setClassName(method.getDeclaringClass().getSimpleName());
        result.setMethodName(method.getName());
        result.setReturnType(method.getReturnType());
        
        // 파라미터 분석
        analyzeParameters(method, result);
        
        // 패턴 감지
        detectConditionPattern(result);
        
        // 템플릿 생성
        generateTemplates(result);
        
        log.debug("메서드 분석 완료: {} → 패턴: {}, 템플릿 수: {}",
            result.getMethodIdentifier(), result.getDetectedPattern(), result.getGeneratedTemplates().size());
        
        return result;
    }

    /**
     * 메서드의 파라미터들을 분석합니다.
     */
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

    /**
     * 메서드에 적용 가능한 조건 패턴을 감지합니다.
     */
    private void detectConditionPattern(MethodAnalysisResult result) {
        // 1. 객체 반환 패턴 체크
        if (isEntityReturnType(result.getReturnType())) {
            result.setDetectedPattern(ConditionPattern.OBJECT_RETURN_PATTERN);
            result.getMetadata().put("canUseReturnObject", true);
            return;
        }
        
        // 2. ID 파라미터 패턴 체크
        Optional<ParameterInfo> idParam = result.getParameters().stream()
            .filter(ParameterInfo::isIdType)
            .findFirst();
            
        if (idParam.isPresent()) {
            result.setDetectedPattern(ConditionPattern.ID_PARAMETER_PATTERN);
            result.getMetadata().put("idParameterIndex", idParam.get().getIndex());
            result.getMetadata().put("idParameterName", idParam.get().getName());
            
            // 엔티티 타입 추론
            String entityType = inferEntityTypeFromMethod(result);
            result.getMetadata().put("entityType", entityType);
            return;
        }
        
        // 3. 범용 패턴 (모든 메서드에 적용 가능)
        result.setDetectedPattern(ConditionPattern.UNIVERSAL_PATTERN);
    }

    /**
     * 감지된 패턴에 따라 SpEL 템플릿을 생성합니다.
     */
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

    /**
     * 객체 반환 패턴용 템플릿 생성
     */
    private void generateObjectReturnTemplates(MethodAnalysisResult result) {
        String entityType = result.getReturnType().getSimpleName();
        
        // 기본 권한 체크 템플릿들
        result.getGeneratedTemplates().add("hasPermission(#returnObject, 'READ')");
        result.getGeneratedTemplates().add("hasPermission(#returnObject, 'UPDATE')");
        result.getGeneratedTemplates().add("hasPermission(#returnObject, 'DELETE')");
        
        // 소유권 체크 템플릿 (엔티티에 owner 필드가 있다고 가정)
        result.getGeneratedTemplates().add("#returnObject.owner == #authentication.name");
        result.getGeneratedTemplates().add("#returnObject.createdBy == #authentication.name");
        
        result.getMetadata().put("templateType", "object_return");
        result.getMetadata().put("entityType", entityType);
    }

    /**
     * ID 파라미터 패턴용 템플릿 생성
     */
    private void generateIdParameterTemplates(MethodAnalysisResult result) {
        String entityType = (String) result.getMetadata().get("entityType");
        String idParamName = (String) result.getMetadata().get("idParameterName");
        
        // ID 기반 권한 체크 템플릿들
        result.getGeneratedTemplates().add(String.format("hasPermission(#%s, '%s', 'UPDATE')", idParamName, entityType));
        result.getGeneratedTemplates().add(String.format("hasPermission(#%s, '%s', 'DELETE')", idParamName, entityType));
        
        // 자기 자신 체크 (User 엔티티의 경우)
        if ("User".equals(entityType)) {
            result.getGeneratedTemplates().add(String.format("#%s == #authentication.id", idParamName));
        }
        
        result.getMetadata().put("templateType", "id_parameter");
        result.getMetadata().put("entityType", entityType);
    }

    /**
     * 범용 패턴용 템플릿 생성
     */
    private void generateUniversalTemplates(MethodAnalysisResult result) {
        // 시간 기반 조건들
        result.getGeneratedTemplates().add("T(java.time.LocalTime).now().hour >= 9 and T(java.time.LocalTime).now().hour <= 18");
        result.getGeneratedTemplates().add("T(java.time.LocalDate).now().dayOfWeek.value <= 5");
        
        // IP 기반 조건들
        result.getGeneratedTemplates().add("#request.remoteAddr matches '^192\\\\.168\\\\..*'");
        result.getGeneratedTemplates().add("#request.remoteAddr matches '^10\\\\..*'");
        
        // 역할 기반 조건들
        result.getGeneratedTemplates().add("hasRole('ADMIN')");
        result.getGeneratedTemplates().add("hasRole('MANAGER')");
        result.getGeneratedTemplates().add("hasAuthority('SYSTEM_ADMIN')");
        
        result.getMetadata().put("templateType", "universal");
    }

    /**
     * 메서드 고유 식별자 생성
     */
    private String generateMethodIdentifier(Method method, String resourceIdentifier) {
        return String.format("%s_%s_%s", 
            resourceIdentifier,
            method.getDeclaringClass().getSimpleName(),
            method.getName());
    }

    /**
     * 타입이 ID 타입인지 확인 (Long, Integer, String 등)
     */
    private boolean isIdType(Class<?> type) {
        return type == Long.class || type == long.class ||
               type == Integer.class || type == int.class ||
               type == String.class;
    }

    /**
     * 타입이 엔티티 타입인지 확인
     */
    private boolean isEntityType(Class<?> type) {
        // 엔티티 패키지나 어노테이션으로 판단
        return type.getPackage() != null && 
               type.getPackage().getName().contains(".entity");
    }

    /**
     * 반환 타입이 엔티티인지 확인
     */
    private boolean isEntityReturnType(Class<?> returnType) {
        return !returnType.equals(void.class) && 
               !returnType.equals(Void.class) &&
               !returnType.isPrimitive() &&
               !returnType.equals(String.class) &&
               isEntityType(returnType);
    }

    /**
     * 메서드명과 파라미터로부터 엔티티 타입 추론
     */
    private String inferEntityTypeFromMethod(MethodAnalysisResult result) {
        String methodName = result.getMethodName();
        
        // 메서드명에서 엔티티 타입 추출 시도
        if (methodName.contains("User")) return "User";
        if (methodName.contains("Project")) return "Project";
        if (methodName.contains("Document")) return "Document";
        if (methodName.contains("Role")) return "Role";
        if (methodName.contains("Permission")) return "Permission";
        
        // 클래스명에서 추출 시도
        String className = result.getClassName();
        if (className.endsWith("Controller")) {
            String entityName = className.replace("Controller", "");
            return entityName;
        }
        
        // 기본값
        return "Entity";
    }

    /**
     * 여러 메서드를 일괄 분석
     */
    public List<MethodAnalysisResult> analyzeMethods(List<Method> methods, String resourceIdentifier) {
        log.info("메서드 일괄 분석 시작: {} 개 메서드", methods.size());
        
        List<MethodAnalysisResult> results = methods.stream()
            .map(method -> analyzeMethod(method, resourceIdentifier))
            .collect(Collectors.toList());
        
        log.info("메서드 일괄 분석 완료: {} 개 결과", results.size());
        return results;
    }
} 