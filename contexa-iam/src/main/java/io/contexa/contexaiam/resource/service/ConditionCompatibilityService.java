package io.contexa.contexaiam.resource.service;

import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexacommon.entity.ManagedResource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


@RequiredArgsConstructor
@Slf4j
public class ConditionCompatibilityService {

    private static final Pattern VARIABLE_PATTERN = Pattern.compile("#(\\w+)");
    
    
    public List<ConditionTemplate> getCompatibleConditions(ManagedResource resource, List<ConditionTemplate> allConditions) {
        if (resource == null) {
            log.warn("리소스가 null입니다. 범용 조건만 반환합니다.");
            return getUniversalConditions(allConditions);
        }

        log.info("조건 호환성 사전 필터링 시작: {}", resource.getResourceIdentifier());
        
        
        Map<ConditionTemplate.ConditionClassification, Long> conditionsByClassification = allConditions.stream()
            .collect(Collectors.groupingBy(
                c -> c.getClassification() != null ? c.getClassification() : ConditionTemplate.ConditionClassification.UNIVERSAL,
                Collectors.counting()));
        
        log.info("입력 조건 분류별 개수: {}", conditionsByClassification);
        
        List<ConditionTemplate> compatibleConditions = new ArrayList<>();
        Set<String> availableVariables = calculateAvailableVariables(resource);
        
        log.info("사용 가능한 변수들: {}", availableVariables);

        int universalApproved = 0, domainFiltered = 0, variableFiltered = 0, abacFiltered = 0;

        for (ConditionTemplate condition : allConditions) {
            log.info("조건 검사: [{}] - 분류=[{}]", condition.getName(), condition.getClassification());
            CompatibilityResult result = checkCompatibility(condition, resource, availableVariables);
            
            if (result.isCompatible()) {
                compatibleConditions.add(condition);
                log.info("호환 조건 추가: {} - {}", condition.getName(), result.getReason());
                if (ConditionTemplate.ConditionClassification.UNIVERSAL.equals(condition.getClassification())) {
                    universalApproved++;
                }
            } else {
                log.warn("호환 불가 조건 제외: {} - {}", condition.getName(), result.getReason());
                if (result.getReason().contains("도메인 컨텍스트가 호환되지 않음")) {
                    domainFiltered++;
                } else if (result.getReason().contains("ABAC 적용 불가능")) {
                    abacFiltered++;
                } else if (result.getReason().contains("변수가 누락")) {
                    variableFiltered++;
                }
            }
        }

        log.info("필터링 완료: 전체 {} 개 중 {} 개 호환 조건 반환", 
            allConditions.size(), compatibleConditions.size());
        log.info("필터링 상세: 범용승인={}, 도메인필터={}, 변수필터={}, ABAC필터={}", 
            universalApproved, domainFiltered, variableFiltered, abacFiltered);

        return compatibleConditions;
    }

    
    public List<ConditionTemplate> getUniversalConditions(List<ConditionTemplate> allConditions) {
        return allConditions.stream()
            .filter(condition -> ConditionTemplate.ConditionClassification.UNIVERSAL.equals(condition.getClassification()))
            .collect(Collectors.toList());
    }

    
    private CompatibilityResult checkCompatibility(ConditionTemplate condition, ManagedResource resource, Set<String> availableVariables) {
        
        
        if (ConditionTemplate.ConditionClassification.UNIVERSAL.equals(condition.getClassification())) {
            return new CompatibilityResult(
                true, 
                "범용 조건 - 즉시 승인", 
                Collections.emptySet(), 
                availableVariables,
                ConditionTemplate.ConditionClassification.UNIVERSAL,
                false 
            );
        }

        
        if (!isAbacApplicableMethod(resource)) {
            return new CompatibilityResult(
                false, 
                "ABAC 적용 불가능한 메서드", 
                Collections.emptySet(), 
                availableVariables,
                condition.getClassification(),
                false
            );
        }

        
        if (!isDomainCompatible(condition, resource)) {
            return new CompatibilityResult(
                false, 
                "도메인 컨텍스트가 호환되지 않음", 
                Collections.emptySet(), 
                availableVariables,
                condition.getClassification(),
                false
            );
        }

        
        Set<String> requiredVariables = extractVariablesFromSpel(condition.getSpelTemplate());
        Set<String> missingVariables = new HashSet<>(requiredVariables);
        missingVariables.removeAll(availableVariables);

        
        boolean isCompatible = missingVariables.isEmpty();
        
        if (isCompatible) {
            return new CompatibilityResult(
                true, 
                "모든 필요 변수 사용 가능", 
                Collections.emptySet(), 
                availableVariables,
                condition.getClassification(),
                shouldRequireAiValidation(condition, requiredVariables)
            );
        } else {
            return new CompatibilityResult(
                false, 
                "필요한 변수가 누락되었습니다: " + String.join(", ", missingVariables), 
                missingVariables, 
                availableVariables,
                condition.getClassification(),
                false
            );
        }
    }

    
    private boolean shouldRequireAiValidation(ConditionTemplate condition, Set<String> requiredVariables) {
        
        if (ConditionTemplate.ConditionClassification.UNIVERSAL.equals(condition.getClassification())) {
            return false;
        }
        
        
        if (ConditionTemplate.ConditionClassification.CUSTOM_COMPLEX.equals(condition.getClassification())) {
            return true;
        }
        
        
        if (ConditionTemplate.ConditionClassification.CONTEXT_DEPENDENT.equals(condition.getClassification())) {
            
            String spelTemplate = condition.getSpelTemplate().toLowerCase();
            return spelTemplate.contains("haspermission") || 
                   spelTemplate.contains("complex") || 
                   requiredVariables.size() > 2;
        }
        
        return false;
    }

    
    private Set<String> extractVariablesFromSpel(String spelTemplate) {
        Set<String> variables = new HashSet<>();
        if (spelTemplate != null) {
            Matcher matcher = VARIABLE_PATTERN.matcher(spelTemplate);
            while (matcher.find()) {
                variables.add("#" + matcher.group(1));
            }
        }
        return variables;
    }

    
    private Set<String> calculateAvailableVariables(ManagedResource resource) {
        Set<String> variables = new HashSet<>();
        
        
        Set<String> universalVars = getAllUniversalVariables();
        variables.addAll(universalVars);
        log.info("🌍 범용 변수 추가: {}", universalVars);
        
        
        Set<String> paramVars = extractParameterVariables(resource);
        variables.addAll(paramVars);
        log.info("파라미터 변수 추가: {}", paramVars);
        
        
        if (hasReturnObject(resource)) {
            variables.add("#returnObject");
            log.info("📤 반환 객체 변수 추가: #returnObject");
        }
        
        log.info("최종 사용 가능한 변수들: {}", variables);
        return variables;
    }

    
    private Set<String> getAllUniversalVariables() {
        return Set.of(
            "#request", "#clientIp", "#session", 
            "#isBusinessHours", "#ai", "#currentTime", "#authentication"
        );
    }

    
    private Set<String> extractParameterVariables(ManagedResource resource) {
        Set<String> variables = new HashSet<>();
        
        try {
            String paramTypes = resource.getParameterTypes();
            log.info("파라미터 타입 원본: '{}'", paramTypes);
            
            if (paramTypes != null && !paramTypes.trim().isEmpty()) {
                if (paramTypes.startsWith("[") && paramTypes.endsWith("]")) {
                    
                    log.info("JSON 배열 형태로 파싱 시도");
                    variables.addAll(extractFromJsonArray(paramTypes));
                } else if (paramTypes.contains(",")) {
                    
                    log.info("쉼표 구분 형태로 파싱 시도");
                    variables.addAll(extractFromCommaSeparated(paramTypes));
                } else if (!paramTypes.equals("[]") && !paramTypes.equals("()")) {
                    
                    log.info("단일 파라미터로 파싱 시도");
                    variables.addAll(extractFromSingleParam(paramTypes));
                } else {
                    log.info("빈 파라미터 리스트");
                }
            } else {
                log.info("파라미터 타입이 null 또는 빈 문자열");
            }
            
            log.info("추출된 파라미터 변수들: {}", variables);
            
        } catch (Exception e) {
            log.warn("파라미터 변수 추출 실패: {}", resource.getResourceIdentifier(), e);
        }
        
        return variables;
    }

    
    private Set<String> extractFromJsonArray(String paramTypes) {
        Set<String> variables = new HashSet<>();
        
        try {
            String content = paramTypes.substring(1, paramTypes.length() - 1).trim();
            log.info("JSON 배열 내용: '{}'", content);
            
            if (content.isEmpty()) {
                log.info("JSON 배열이 비어있음");
                return variables;
            }
            
            String[] types = content.split(",");
            log.info("분할된 타입들: {}", Arrays.toString(types));
            
            for (String type : types) {
                String cleanType = type.trim().replaceAll("[\\\"']", "");
                log.info("정리된 타입: '{}'", cleanType);
                
                String paramName = inferParameterNameFromType(cleanType);
                log.info("추론된 파라미터명: '{}'", paramName);
                
                if (paramName != null) {
                    String variable = "#" + paramName;
                    variables.add(variable);
                    log.info("변수 추가: '{}'", variable);
                }
            }
            
        } catch (Exception e) {
            log.warn("JSON 배열 파라미터 파싱 실패: {}", paramTypes, e);
        }
        
        log.info("JSON 배열에서 추출된 최종 변수들: {}", variables);
        return variables;
    }

    
    private Set<String> extractFromCommaSeparated(String paramTypes) {
        Set<String> variables = new HashSet<>();
        
        String[] types = paramTypes.split(",");
        for (String type : types) {
            String cleanType = type.trim();
            if (cleanType.contains("<")) {
                cleanType = cleanType.substring(0, cleanType.indexOf("<"));
            }
            
            String paramName = inferParameterNameFromType(cleanType);
            if (paramName != null) {
                variables.add("#" + paramName);
            }
        }
        
        return variables;
    }

    
    private Set<String> extractFromSingleParam(String paramTypes) {
        Set<String> variables = new HashSet<>();
        
        String cleanType = paramTypes.trim();
        if (cleanType.contains("<")) {
            cleanType = cleanType.substring(0, cleanType.indexOf("<"));
        }
        
        String paramName = inferParameterNameFromType(cleanType);
        if (paramName != null) {
            variables.add("#" + paramName);
        }
        
        return variables;
    }

    
    private String inferParameterNameFromType(String type) {
        if (type == null || type.trim().isEmpty()) {
            return null;
        }
        
        String simpleType = type.substring(type.lastIndexOf('.') + 1);
        
        Map<String, String> typeToParamMap = new HashMap<>();
        
        
        typeToParamMap.put("Long", "id");
        typeToParamMap.put("Integer", "id");
        typeToParamMap.put("String", "name");
        typeToParamMap.put("UUID", "id");
        
        
        typeToParamMap.put("Group", "group");
        typeToParamMap.put("User", "user");
        typeToParamMap.put("Users", "user");
        typeToParamMap.put("UserDto", "userDto");
        typeToParamMap.put("Document", "document");
        typeToParamMap.put("Permission", "permission");
        typeToParamMap.put("Role", "role");
        typeToParamMap.put("Policy", "policy");
        
        String paramName = typeToParamMap.get(simpleType);
        if (paramName != null) {
            return paramName;
        }
        
        
        return Character.toLowerCase(simpleType.charAt(0)) + simpleType.substring(1);
    }

    
    private boolean hasReturnObject(ManagedResource resource) {
        String returnType = resource.getReturnType();
        return returnType != null && 
               !returnType.equals("void") && 
               !returnType.equals("java.lang.Void");
    }

    
    private boolean isDomainCompatible(ConditionTemplate condition, ManagedResource resource) {
        String resourceIdentifier = resource.getResourceIdentifier().toLowerCase();
        String conditionName = condition.getName().toLowerCase();
        String conditionSpel = condition.getSpelTemplate() != null ? condition.getSpelTemplate().toLowerCase() : "";
        
        log.info("도메인 호환성 검사: 리소스=[{}], 조건=[{}], SpEL=[{}], 분류=[{}]", 
            resourceIdentifier, conditionName, conditionSpel, condition.getClassification());
        
        
        boolean isGroupResource = isGroupRelatedResource(resourceIdentifier);
        boolean isUserResource = isUserRelatedResource(resourceIdentifier);
        boolean isRoleResource = isRoleRelatedResource(resourceIdentifier);
        boolean isPermissionResource = isPermissionRelatedResource(resourceIdentifier);
        
        log.info("리소스 분류: 그룹={}, 사용자={}, 역할={}, 권한={}", 
            isGroupResource, isUserResource, isRoleResource, isPermissionResource);
        
        
        boolean isGroupCondition = isGroupRelatedCondition(conditionName, conditionSpel);
        boolean isUserCondition = isUserRelatedCondition(conditionName, conditionSpel);
        boolean isRoleCondition = isRoleRelatedCondition(conditionName, conditionSpel);
        boolean isPermissionCondition = isPermissionRelatedCondition(conditionName, conditionSpel);
        
        log.info("조건 분류: 그룹={}, 사용자={}, 역할={}, 권한={}", 
            isGroupCondition, isUserCondition, isRoleCondition, isPermissionCondition);
        
        
        if (ConditionTemplate.ConditionClassification.UNIVERSAL.equals(condition.getClassification())) {
            
            boolean hasSpecificDomain = isGroupCondition || isUserCondition || isRoleCondition || isPermissionCondition;
            if (hasSpecificDomain) {
                log.info("UNIVERSAL 조건이지만 특정 도메인 키워드 감지 - 도메인 검사 수행: {}", conditionName);
                
            } else {
                log.info("순수 범용 조건으로 승인: {}", conditionName);
                return true;
            }
        }
        
        
        if (isGroupResource && isGroupCondition) {
            log.info("그룹 리소스 + 그룹 조건 매칭");
            return true;
        }
        
        if (isUserResource && isUserCondition) {
            log.info("사용자 리소스 + 사용자 조건 매칭");
            return true;
        }
        
        if (isRoleResource && isRoleCondition) {
            log.info("역할 리소스 + 역할 조건 매칭");
            return true;
        }
        
        if (isPermissionResource && isPermissionCondition) {
            log.info("권한 리소스 + 권한 조건 매칭");
            return true;
        }
        
        
        boolean isObjectBasedCondition = isObjectBasedCondition(conditionName, conditionSpel);
        if (isObjectBasedCondition && hasObjectIdParameter(resource)) {
            
            if (isGroupResource && !isGroupCondition && (isUserCondition || isRoleCondition || isPermissionCondition)) {
                log.warn("🚫 그룹 리소스에서 다른 도메인의 객체 기반 조건 차단: {}", conditionName);
                return false;
            }
            if (isUserResource && !isUserCondition && (isGroupCondition || isRoleCondition || isPermissionCondition)) {
                log.warn("🚫 사용자 리소스에서 다른 도메인의 객체 기반 조건 차단: {}", conditionName);
                return false;
            }
            if (isRoleResource && !isRoleCondition && (isGroupCondition || isUserCondition || isPermissionCondition)) {
                log.warn("🚫 역할 리소스에서 다른 도메인의 객체 기반 조건 차단: {}", conditionName);
                return false;
            }
            if (isPermissionResource && !isPermissionCondition && (isGroupCondition || isUserCondition || isRoleCondition)) {
                log.warn("🚫 권한 리소스에서 다른 도메인의 객체 기반 조건 차단: {}", conditionName);
                return false;
            }
            
            log.info("객체 기반 조건 + ID 파라미터 매칭 (도메인 일치)");
            return true;
        }
        
        
        if (isGroupResource) {
            if (isUserCondition || isRoleCondition || isPermissionCondition) {
                log.warn("🚫 그룹 리소스에 다른 도메인 조건 차단: 사용자={}, 역할={}, 권한={}", 
                    isUserCondition, isRoleCondition, isPermissionCondition);
                return false;
            }
        }
        
        if (isUserResource) {
            if (isGroupCondition || isRoleCondition || isPermissionCondition) {
                log.warn("🚫 사용자 리소스에 다른 도메인 조건 차단: 그룹={}, 역할={}, 권한={}", 
                    isGroupCondition, isRoleCondition, isPermissionCondition);
                return false;
            }
        }
        
        if (isRoleResource) {
            if (isGroupCondition || isUserCondition || isPermissionCondition) {
                log.warn("🚫 역할 리소스에 다른 도메인 조건 차단: 그룹={}, 사용자={}, 권한={}", 
                    isGroupCondition, isUserCondition, isPermissionCondition);
                return false;
            }
        }
        
        if (isPermissionResource) {
            if (isGroupCondition || isUserCondition || isRoleCondition) {
                log.warn("🚫 권한 리소스에 다른 도메인 조건 차단: 그룹={}, 사용자={}, 역할={}", 
                    isGroupCondition, isUserCondition, isRoleCondition);
                return false;
            }
        }
        
        
        if (condition.getSourceMethod() != null) {
            String sourceMethod = condition.getSourceMethod().toLowerCase();
            if (isGroupResource && (sourceMethod.contains("group") || sourceMethod.contains("그룹"))) {
                log.info("소스 메서드 기반 그룹 도메인 매칭: {}", condition.getSourceMethod());
                return true;
            }
            if (isUserResource && (sourceMethod.contains("user") || sourceMethod.contains("사용자"))) {
                log.info("소스 메서드 기반 사용자 도메인 매칭: {}", condition.getSourceMethod());
                return true;
            }
            if (isRoleResource && (sourceMethod.contains("role") || sourceMethod.contains("역할"))) {
                log.info("소스 메서드 기반 역할 도메인 매칭: {}", condition.getSourceMethod());
                return true;
            }
            if (isPermissionResource && (sourceMethod.contains("permission") || sourceMethod.contains("권한"))) {
                log.info("소스 메서드 기반 권한 도메인 매칭: {}", condition.getSourceMethod());
                return true;
            }
        }
        
        log.warn("도메인 호환성 불일치: 리소스[그룹={}, 사용자={}, 역할={}, 권한={}], 조건[그룹={}, 사용자={}, 역할={}, 권한={}, 객체기반={}], 소스메서드=[{}]",
            isGroupResource, isUserResource, isRoleResource, isPermissionResource,
            isGroupCondition, isUserCondition, isRoleCondition, isPermissionCondition, isObjectBasedCondition,
            condition.getSourceMethod());
        
        return false;
    }
    
    private boolean isGroupRelatedResource(String resourceIdentifier) {
        return resourceIdentifier.contains("group") || resourceIdentifier.contains("그룹");
    }
    
    private boolean isUserRelatedResource(String resourceIdentifier) {
        return resourceIdentifier.contains("user") || resourceIdentifier.contains("사용자") || 
               resourceIdentifier.contains("member") || resourceIdentifier.contains("멤버");
    }
    
    private boolean isRoleRelatedResource(String resourceIdentifier) {
        return resourceIdentifier.contains("role") || resourceIdentifier.contains("역할");
    }
    
    private boolean isPermissionRelatedResource(String resourceIdentifier) {
        return resourceIdentifier.contains("permission") || resourceIdentifier.contains("권한");
    }
    
    private boolean isGroupRelatedCondition(String conditionName, String conditionSpel) {
        boolean nameMatch = conditionName.contains("그룹") || conditionName.contains("group") ||
                           conditionName.contains("팀") || conditionName.contains("team");
        boolean spelMatch = conditionSpel.contains("#group") || conditionSpel.contains("group") ||
                           conditionSpel.contains("'group'") || conditionSpel.contains("\"group\"");
        
        boolean result = nameMatch || spelMatch;
        log.debug("그룹 조건 검사: 이름=[{}], SpEL=[{}] → 이름매치={}, SpEL매치={}, 결과={}", 
            conditionName, conditionSpel, nameMatch, spelMatch, result);
        return result;
    }
    
    private boolean isUserRelatedCondition(String conditionName, String conditionSpel) {
        boolean nameMatch = conditionName.contains("사용자") || conditionName.contains("user") ||
                           conditionName.contains("소유자") || conditionName.contains("owner") ||
                           conditionName.contains("멤버") || conditionName.contains("member");
        boolean spelMatch = conditionSpel.contains("#user") || conditionSpel.contains("user") ||
                           conditionSpel.contains("#owner") || conditionSpel.contains("owner") ||
                           conditionSpel.contains("'user'") || conditionSpel.contains("\"user\"");
        
        boolean result = nameMatch || spelMatch;
        log.debug("사용자 조건 검사: 이름=[{}], SpEL=[{}] → 이름매치={}, SpEL매치={}, 결과={}", 
            conditionName, conditionSpel, nameMatch, spelMatch, result);
        return result;
    }
    
    private boolean isRoleRelatedCondition(String conditionName, String conditionSpel) {
        boolean nameMatch = conditionName.contains("역할") || conditionName.contains("role") ||
                           conditionName.contains("직책") || conditionName.contains("position");
        boolean spelMatch = conditionSpel.contains("#role") || conditionSpel.contains("role") ||
                           conditionSpel.contains("'role'") || conditionSpel.contains("\"role\"");
        
        boolean result = nameMatch || spelMatch;
        log.debug("역할 조건 검사: 이름=[{}], SpEL=[{}] → 이름매치={}, SpEL매치={}, 결과={}", 
            conditionName, conditionSpel, nameMatch, spelMatch, result);
        return result;
    }
    
    private boolean isPermissionRelatedCondition(String conditionName, String conditionSpel) {
        boolean nameMatch = conditionName.contains("권한") || conditionName.contains("permission") ||
                           conditionName.contains("허가") || conditionName.contains("authority");
        boolean spelMatch = conditionSpel.contains("#permission") || conditionSpel.contains("permission") ||
                           conditionSpel.contains("'permission'") || conditionSpel.contains("\"permission\"") ||
                           conditionSpel.contains("hasauthority") || conditionSpel.contains("hasrole");
        
        boolean result = nameMatch || spelMatch;
        log.debug("권한 조건 검사: 이름=[{}], SpEL=[{}] → 이름매치={}, SpEL매치={}, 결과={}", 
            conditionName, conditionSpel, nameMatch, spelMatch, result);
        return result;
    }
    
    private boolean isObjectBasedCondition(String conditionName, String conditionSpel) {
        return conditionName.contains("소유자") || conditionName.contains("owner") ||
               conditionName.contains("접근") || conditionName.contains("access") ||
               conditionSpel.contains("#id") || conditionSpel.contains("#returnobject");
    }
    
    private boolean hasObjectIdParameter(ManagedResource resource) {
        String paramTypes = resource.getParameterTypes();
        if (paramTypes == null) return false;
        
        return paramTypes.toLowerCase().contains("long") || 
               paramTypes.toLowerCase().contains("id") ||
               paramTypes.toLowerCase().contains("integer");
    }

    
    private boolean isAbacApplicableMethod(ManagedResource resource) {
        if (ManagedResource.ResourceType.URL.equals(resource.getResourceType())) {
            return true;
        }
        
        if (!ManagedResource.ResourceType.METHOD.equals(resource.getResourceType())) {
            return false;
        }
        
        String resourceIdentifier = resource.getResourceIdentifier();
        String parameterTypes = resource.getParameterTypes();
        
        
        if (parameterTypes == null || parameterTypes.trim().isEmpty() || 
            parameterTypes.equals("[]") || parameterTypes.equals("()")) {
            
            
            if (hasReturnObject(resource)) {
                return true;
            }
            
            return false;
        }
        
        
        if (resourceIdentifier != null) {
            String methodName = extractMethodName(resourceIdentifier).toLowerCase();
            if (methodName.contains("getall") || methodName.contains("findall") || 
                methodName.contains("listall") || methodName.contains("all")) {
                return false;
            }
        }
        
        return true;
    }

    
    private String extractMethodName(String resourceIdentifier) {
        if (resourceIdentifier == null) return "";
        
        int lastDotIndex = resourceIdentifier.lastIndexOf('.');
        if (lastDotIndex == -1) return resourceIdentifier;
        
        String methodPart = resourceIdentifier.substring(lastDotIndex + 1);
        int parenIndex = methodPart.indexOf('(');
        if (parenIndex == -1) return methodPart;
        
        return methodPart.substring(0, parenIndex);
    }

    
    public CompatibilityResult checkCompatibility(ConditionTemplate condition, ManagedResource resource) {
        if (condition == null || resource == null) {
            return new CompatibilityResult(false, "조건 또는 리소스가 null입니다.", 
                Collections.emptySet(), Collections.emptySet(), 
                ConditionTemplate.ConditionClassification.CUSTOM_COMPLEX, false);
        }

        Set<String> availableVariables = calculateAvailableVariables(resource);
        return checkCompatibility(condition, resource, availableVariables);
    }

    
    public Map<Long, CompatibilityResult> checkBatchCompatibility(List<ConditionTemplate> conditions, 
                                                                ManagedResource resource) {
        Map<Long, CompatibilityResult> results = new HashMap<>();
        
        for (ConditionTemplate condition : conditions) {
            CompatibilityResult result = checkCompatibility(condition, resource);
            results.put(condition.getId(), result);
        }
        
        log.debug("배치 호환성 검사 완료: {} 개 조건, 호환 가능: {} 개", 
            conditions.size(), 
            results.values().stream().mapToInt(r -> r.isCompatible() ? 1 : 0).sum());
        
        return results;
    }

    
    public Map<ConditionTemplate.RiskLevel, List<ConditionTemplate>> groupByRiskLevel(List<ConditionTemplate> conditions) {
        return conditions.stream()
            .collect(Collectors.groupingBy(
                condition -> condition.getRiskLevel() != null ? 
                    condition.getRiskLevel() : ConditionTemplate.RiskLevel.LOW));
    }
} 