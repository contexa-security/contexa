package io.contexa.contexaiam.resource.service;

import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexacommon.entity.ManagedResource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 🚀조건 호환성 서비스
 * 
 * 기존 방식: 사용자가 조건을 드래그할 때마다 하나씩 검증
 * 새로운 방식: 권한 선택 시 호환되는 조건만 사전 필터링하여 제공
 * 
 * AI 사용 영역:
 * - 복잡한 정책 조합 추천
 * - 보안 위험도 분석
 * - 정책 충돌 감지
 * - 자연어 → 정책 변환
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ConditionCompatibilityService {

    private static final Pattern VARIABLE_PATTERN = Pattern.compile("#(\\w+)");
    
    /**
     * 핵심 메서드: 특정 리소스와 호환되는 조건들만 반환
     * 
     * @param resource 대상 리소스
     * @param allConditions 모든 조건 템플릿
     * @return 호환되는 조건들만 필터링된 리스트
     */
    public List<ConditionTemplate> getCompatibleConditions(ManagedResource resource, List<ConditionTemplate> allConditions) {
        if (resource == null) {
            log.warn("리소스가 null입니다. 범용 조건만 반환합니다.");
            return getUniversalConditions(allConditions);
        }

        log.info("조건 호환성 사전 필터링 시작: {}", resource.getResourceIdentifier());
        
        // 조건들을 분류별로 집계
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

    /**
     * 🌟 범용 조건들만 반환 (항상 호환됨)
     */
    public List<ConditionTemplate> getUniversalConditions(List<ConditionTemplate> allConditions) {
        return allConditions.stream()
            .filter(condition -> ConditionTemplate.ConditionClassification.UNIVERSAL.equals(condition.getClassification()))
            .collect(Collectors.toList());
    }

    /**
     * 개별 조건의 호환성 검사 (내부용)
     */
    private CompatibilityResult checkCompatibility(ConditionTemplate condition, ManagedResource resource, Set<String> availableVariables) {
        
        // 1. 범용 조건은 항상 호환됨 (즉시 승인)
        if (ConditionTemplate.ConditionClassification.UNIVERSAL.equals(condition.getClassification())) {
            return new CompatibilityResult(
                true, 
                "범용 조건 - 즉시 승인", 
                Collections.emptySet(), 
                availableVariables,
                ConditionTemplate.ConditionClassification.UNIVERSAL,
                false // AI 검증 불필요
            );
        }

        // 2. 메서드가 ABAC 적용 가능한지 검사
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

        // 3. 도메인 컨텍스트 호환성 검사 (새로 추가)
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

        // 4. 필요한 변수들 추출
        Set<String> requiredVariables = extractVariablesFromSpel(condition.getSpelTemplate());
        Set<String> missingVariables = new HashSet<>(requiredVariables);
        missingVariables.removeAll(availableVariables);

        // 5. 모든 필요한 변수가 있는지 확인
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

    /**
     * AI 검증이 필요한지 판단
     */
    private boolean shouldRequireAiValidation(ConditionTemplate condition, Set<String> requiredVariables) {
        // 범용 조건은 AI 검증 불필요
        if (ConditionTemplate.ConditionClassification.UNIVERSAL.equals(condition.getClassification())) {
            return false;
        }
        
        // 복잡한 조건이나 커스텀 조건은 AI 검증 필요
        if (ConditionTemplate.ConditionClassification.CUSTOM_COMPLEX.equals(condition.getClassification())) {
            return true;
        }
        
        // 컨텍스트 의존 조건 중 복잡한 것들은 AI 검증 필요
        if (ConditionTemplate.ConditionClassification.CONTEXT_DEPENDENT.equals(condition.getClassification())) {
            // hasPermission 같은 복잡한 조건은 AI 검증
            String spelTemplate = condition.getSpelTemplate().toLowerCase();
            return spelTemplate.contains("haspermission") || 
                   spelTemplate.contains("complex") || 
                   requiredVariables.size() > 2;
        }
        
        return false;
    }

    /**
     * SpEL 표현식에서 변수 추출
     */
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

    /**
     * 리소스에서 사용 가능한 변수들 계산 (디버깅 강화)
     */
    private Set<String> calculateAvailableVariables(ManagedResource resource) {
        Set<String> variables = new HashSet<>();
        
        // 항상 사용 가능한 범용 변수들
        Set<String> universalVars = getAllUniversalVariables();
        variables.addAll(universalVars);
        log.info("🌍 범용 변수 추가: {}", universalVars);
        
        // 파라미터에서 추출한 변수들
        Set<String> paramVars = extractParameterVariables(resource);
        variables.addAll(paramVars);
        log.info("파라미터 변수 추가: {}", paramVars);
        
        // 반환 객체가 있는 경우
        if (hasReturnObject(resource)) {
            variables.add("#returnObject");
            log.info("📤 반환 객체 변수 추가: #returnObject");
        }
        
        log.info("최종 사용 가능한 변수들: {}", variables);
        return variables;
    }

    /**
     * 🌍 범용 변수들 (항상 사용 가능)
     */
    private Set<String> getAllUniversalVariables() {
        return Set.of(
            "#request", "#clientIp", "#session", 
            "#isBusinessHours", "#ai", "#currentTime", "#authentication"
        );
    }

    /**
     * 메서드 파라미터에서 변수들을 추출 (디버깅 강화)
     */
    private Set<String> extractParameterVariables(ManagedResource resource) {
        Set<String> variables = new HashSet<>();
        
        try {
            String paramTypes = resource.getParameterTypes();
            log.info("파라미터 타입 원본: '{}'", paramTypes);
            
            if (paramTypes != null && !paramTypes.trim().isEmpty()) {
                if (paramTypes.startsWith("[") && paramTypes.endsWith("]")) {
                    // JSON 배열 형태: ["java.lang.Long", "java.util.List"]
                    log.info("JSON 배열 형태로 파싱 시도");
                    variables.addAll(extractFromJsonArray(paramTypes));
                } else if (paramTypes.contains(",")) {
                    // 쉼표 구분 형태: Long,List<String>
                    log.info("쉼표 구분 형태로 파싱 시도");
                    variables.addAll(extractFromCommaSeparated(paramTypes));
                } else if (!paramTypes.equals("[]") && !paramTypes.equals("()")) {
                    // 단일 파라미터
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

    /**
     * JSON 배열에서 파라미터 변수 추출 (디버깅 강화)
     */
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

    /**
     * 쉼표 구분 파라미터에서 변수 추출
     */
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

    /**
     * 단일 파라미터에서 변수 추출
     */
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

    /**
     * 타입으로부터 파라미터명을 추론
     */
    private String inferParameterNameFromType(String type) {
        if (type == null || type.trim().isEmpty()) {
            return null;
        }
        
        String simpleType = type.substring(type.lastIndexOf('.') + 1);
        
        Map<String, String> typeToParamMap = new HashMap<>();
        
        // ID 타입들
        typeToParamMap.put("Long", "id");
        typeToParamMap.put("Integer", "id");
        typeToParamMap.put("String", "name");
        typeToParamMap.put("UUID", "id");
        
        // 도메인 객체들
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
        
        // 매핑되지 않은 경우 타입명을 소문자로 변환
        return Character.toLowerCase(simpleType.charAt(0)) + simpleType.substring(1);
    }

    /**
     * 반환 객체가 있는지 확인
     */
    private boolean hasReturnObject(ManagedResource resource) {
        String returnType = resource.getReturnType();
        return returnType != null && 
               !returnType.equals("void") && 
               !returnType.equals("java.lang.Void");
    }

    /**
     * 도메인 컨텍스트 호환성 검사
     * 그룹 권한에는 그룹 관련 조건만, 사용자 권한에는 사용자 관련 조건만 표시
     */
    private boolean isDomainCompatible(ConditionTemplate condition, ManagedResource resource) {
        String resourceIdentifier = resource.getResourceIdentifier().toLowerCase();
        String conditionName = condition.getName().toLowerCase();
        String conditionSpel = condition.getSpelTemplate() != null ? condition.getSpelTemplate().toLowerCase() : "";
        
        log.info("도메인 호환성 검사: 리소스=[{}], 조건=[{}], SpEL=[{}], 분류=[{}]", 
            resourceIdentifier, conditionName, conditionSpel, condition.getClassification());
        
        // 그룹 관련 리소스인지 확인
        boolean isGroupResource = isGroupRelatedResource(resourceIdentifier);
        boolean isUserResource = isUserRelatedResource(resourceIdentifier);
        boolean isRoleResource = isRoleRelatedResource(resourceIdentifier);
        boolean isPermissionResource = isPermissionRelatedResource(resourceIdentifier);
        
        log.info("리소스 분류: 그룹={}, 사용자={}, 역할={}, 권한={}", 
            isGroupResource, isUserResource, isRoleResource, isPermissionResource);
        
        // 조건이 그룹 관련인지 확인
        boolean isGroupCondition = isGroupRelatedCondition(conditionName, conditionSpel);
        boolean isUserCondition = isUserRelatedCondition(conditionName, conditionSpel);
        boolean isRoleCondition = isRoleRelatedCondition(conditionName, conditionSpel);
        boolean isPermissionCondition = isPermissionRelatedCondition(conditionName, conditionSpel);
        
        log.info("조건 분류: 그룹={}, 사용자={}, 역할={}, 권한={}", 
            isGroupCondition, isUserCondition, isRoleCondition, isPermissionCondition);
        
        // 범용 조건은 모든 도메인과 호환 (단, 의미적 도메인 검사도 수행)
        if (ConditionTemplate.ConditionClassification.UNIVERSAL.equals(condition.getClassification())) {
            // UNIVERSAL 조건이라도 의미적으로 특정 도메인에 특화된 경우 필터링
            boolean hasSpecificDomain = isGroupCondition || isUserCondition || isRoleCondition || isPermissionCondition;
            if (hasSpecificDomain) {
                log.info("UNIVERSAL 조건이지만 특정 도메인 키워드 감지 - 도메인 검사 수행: {}", conditionName);
                // 도메인 검사를 계속 수행
            } else {
                log.info("순수 범용 조건으로 승인: {}", conditionName);
                return true;
            }
        }
        
        // 도메인별 매칭 규칙 - 완전 일치 우선
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
        
        // 일반적인 객체 기반 조건들 (ID 기반 접근제어) - 도메인 제약 추가
        boolean isObjectBasedCondition = isObjectBasedCondition(conditionName, conditionSpel);
        if (isObjectBasedCondition && hasObjectIdParameter(resource)) {
            // 🚫 객체 기반 조건도 도메인 일치 검사 적용
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
        
        // 🚫 엄격한 도메인 분리: 다른 도메인 조건은 차단
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
        
        // 마지막 시도: 소스 메서드 기반 도메인 추론
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

    /**
     * ABAC 적용 가능한 메서드인지 판단
     */
    private boolean isAbacApplicableMethod(ManagedResource resource) {
        if (ManagedResource.ResourceType.URL.equals(resource.getResourceType())) {
            return true;
        }
        
        if (!ManagedResource.ResourceType.METHOD.equals(resource.getResourceType())) {
            return false;
        }
        
        String resourceIdentifier = resource.getResourceIdentifier();
        String parameterTypes = resource.getParameterTypes();
        
        // 파라미터가 없는 메서드는 ABAC 적용 불가
        if (parameterTypes == null || parameterTypes.trim().isEmpty() || 
            parameterTypes.equals("[]") || parameterTypes.equals("()")) {
            
            // 단, 반환 객체가 있으면 Post-Authorization 가능
            if (hasReturnObject(resource)) {
                return true;
            }
            
            return false;
        }
        
        // getAll, findAll 등 전체 조회 메서드는 ABAC 적용 불가
        if (resourceIdentifier != null) {
            String methodName = extractMethodName(resourceIdentifier).toLowerCase();
            if (methodName.contains("getall") || methodName.contains("findall") || 
                methodName.contains("listall") || methodName.contains("all")) {
                return false;
            }
        }
        
        return true;
    }

    /**
     * 리소스 식별자에서 메서드명 추출
     */
    private String extractMethodName(String resourceIdentifier) {
        if (resourceIdentifier == null) return "";
        
        int lastDotIndex = resourceIdentifier.lastIndexOf('.');
        if (lastDotIndex == -1) return resourceIdentifier;
        
        String methodPart = resourceIdentifier.substring(lastDotIndex + 1);
        int parenIndex = methodPart.indexOf('(');
        if (parenIndex == -1) return methodPart;
        
        return methodPart.substring(0, parenIndex);
    }

    /**
     * 기존 코드 호환성을 위한 메서드 (2 파라미터)
     */
    public CompatibilityResult checkCompatibility(ConditionTemplate condition, ManagedResource resource) {
        if (condition == null || resource == null) {
            return new CompatibilityResult(false, "조건 또는 리소스가 null입니다.", 
                Collections.emptySet(), Collections.emptySet(), 
                ConditionTemplate.ConditionClassification.CUSTOM_COMPLEX, false);
        }

        Set<String> availableVariables = calculateAvailableVariables(resource);
        return checkCompatibility(condition, resource, availableVariables);
    }

    /**
     * 기존 코드 호환성을 위한 배치 호환성 검사
     */
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

    /**
     * 기존 코드 호환성을 위한 위험도별 그룹화
     */
    public Map<ConditionTemplate.RiskLevel, List<ConditionTemplate>> groupByRiskLevel(List<ConditionTemplate> conditions) {
        return conditions.stream()
            .collect(Collectors.groupingBy(
                condition -> condition.getRiskLevel() != null ? 
                    condition.getRiskLevel() : ConditionTemplate.RiskLevel.LOW));
    }
} 