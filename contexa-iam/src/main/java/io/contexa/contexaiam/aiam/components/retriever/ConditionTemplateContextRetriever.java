package io.contexa.contexaiam.aiam.components.retriever;

import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.labs.condition.ConditionTemplateVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.advisor.RetrievalAugmentationAdvisor;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.rag.retrieval.search.VectorStoreDocumentRetriever;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Slf4j
public class ConditionTemplateContextRetriever extends ContextRetriever {
    
    private final ContextRetrieverRegistry registry;
    private final ConditionTemplateVectorService vectorService;
    
    @Autowired(required = false)
    private ChatClient.Builder chatClientBuilder;
    
    @Value("${spring.ai.rag.template.similarity-threshold:0.8}")
    private double templateSimilarityThreshold;
    
    @Value("${spring.ai.rag.template.top-k:10}")
    private int templateTopK;
    
    private RetrievalAugmentationAdvisor templateAdvisor;
    
    
    public static class MethodSignature {
        public final String methodName;
        public final String parameterInfo;
        public final String resourceType;

        public MethodSignature(String methodName, String parameterInfo, String resourceType) {
            this.methodName = methodName;
            this.parameterInfo = parameterInfo;
            this.resourceType = resourceType;
        }
    }
    
    public ConditionTemplateContextRetriever(VectorStore vectorStore, 
                                            ContextRetrieverRegistry registry,
                                            ConditionTemplateVectorService vectorService) {
        super(vectorStore);
        this.registry = registry;
        this.vectorService = vectorService;
    }
    
    
    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        log.info("ApplicationContext refreshed. Initializing ConditionTemplateContextRetriever...");
        registerSelf();
    }

    private void registerSelf() {
        
        if (chatClientBuilder != null && vectorStore != null) {
            createTemplateAdvisor();
        }

        registry.registerRetriever(ConditionTemplateContext.class, this);
        log.info("ConditionTemplateContextRetriever 자동 등록 완료 (Spring AI RAG 지원)");
    }
    
    
    private void createTemplateAdvisor() {
        
        QueryTransformer templateQueryTransformer = new TemplateQueryTransformer(chatClientBuilder);
        
        
        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
            filterBuilder.in("documentType", "template", "condition", "spel", "expression"),
            filterBuilder.gte("relevanceScore", 0.75)
        ).build();
        
        
        VectorStoreDocumentRetriever retriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(templateSimilarityThreshold)
            .topK(templateTopK)
            .filterExpression(filter)
            .build();
        
        
        templateAdvisor = RetrievalAugmentationAdvisor.builder()
            .documentRetriever(retriever)
            .queryTransformers(templateQueryTransformer)
            .build();
        
        
        registerDomainAdvisor(ConditionTemplateContext.class, templateAdvisor);
    }
    
    
    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        log.debug("ConditionTemplateContextRetriever.retrieveContext 호출됨");
        
        
        if (request.getContext() instanceof ConditionTemplateContext) {
            
            ContextRetrievalResult ragResult = null;
            if (templateAdvisor != null) {
                ragResult = super.retrieveContext(request);
            }
            
            String contextInfo = retrieveConditionTemplateContext(
                (AIRequest<ConditionTemplateContext>) request,
                ragResult != null ? ragResult.getDocuments() : List.of()
            );
            
            Map<String, Object> metadata = new HashMap<>();
            if (ragResult != null) {
                metadata.putAll(ragResult.getMetadata());
            }
            metadata.put("retrieverType", "ConditionTemplateContextRetriever");
            metadata.put("timestamp", System.currentTimeMillis());
            metadata.put("ragEnabled", templateAdvisor != null);
            
            return new ContextRetrievalResult(
                contextInfo,
                ragResult != null ? ragResult.getDocuments() : List.of(),
                metadata
            );
        }
        
        
        return super.retrieveContext(request);
    }
    
    
    public String retrieveConditionTemplateContext(AIRequest<ConditionTemplateContext> request, List<Document> ragDocuments) {
        log.info("조건 템플릿 컨텍스트 검색 시작: {}", request.getRequestId());
        
        try {
            ConditionTemplateContext context = request.getContext();
            
            
            try {
                vectorService.storeConditionContext(context);
                log.debug("💾 VectorService에 조건 템플릿 컨텍스트 저장 완료");
            } catch (Exception e) {
                log.warn("VectorService 컨텍스트 저장 실패: {}", e.getMessage());
            }
            
            if ("universal".equals(context.getTemplateType())) {
                return retrieveUniversalTemplateContext(context, ragDocuments);
            } else if ("specific".equals(context.getTemplateType())) {
                
                return generateMethodInfo(context, context.getResourceIdentifier(), context.getMethodInfo(), ragDocuments);
            } else {
                log.warn("알 수 없는 템플릿 타입: {}", context.getTemplateType());
                return getDefaultContext();
            }
            
        } catch (Exception e) {
            log.error("조건 템플릿 컨텍스트 검색 실패", e);
            return getDefaultContext();
        }
    }
    
    
    private String retrieveUniversalTemplateContext(ConditionTemplateContext context, List<Document> ragDocuments) {
        log.debug("범용 조건 템플릿 컨텍스트 검색");
        
        StringBuilder contextBuilder = new StringBuilder();
        String baseContext = """
        ## 범용 조건 템플릿 컨텍스트
        
        ### Spring Security 기본 표현식
        - isAuthenticated(): 사용자 인증 상태 확인
        - hasRole('ROLE_ADMIN'): 특정 역할 보유 확인
        - hasAuthority('READ_PRIVILEGE'): 특정 권한 보유 확인
        
        ### 시간 기반 제약
        - T(java.time.LocalTime).now().hour >= 9: 업무시간 제약
        - T(java.time.DayOfWeek).from(T(java.time.LocalDate).now()) != T(java.time.DayOfWeek).SATURDAY: 평일 제약
        
        ### ABAC 속성 기반
        - #authentication.principal.department == 'IT': 부서 기반 제약
        - #request.remoteAddr.startsWith('192.168.'): IP 기반 제약
        
        ### 네이밍 가이드라인
        - "~상태 확인": 인증/권한 상태
        - "~역할 확인": 역할 기반 제약  
        - "~접근 제한": 시간/위치 기반 제약
        - "권한" 용어 사용 금지!
        """;
        
        contextBuilder.append(baseContext);
        
        
        if (ragDocuments != null && !ragDocuments.isEmpty()) {
            contextBuilder.append("\n\n### RAG 기반 템플릿 참조\n");
            for (int i = 0; i < Math.min(3, ragDocuments.size()); i++) {
                Document doc = ragDocuments.get(i);
                contextBuilder.append("- ").append(doc.getText().substring(0, Math.min(200, doc.getText().length())));
                if (doc.getText().length() > 200) {
                    contextBuilder.append("...");
                }
                contextBuilder.append("\n");
            }
        }
        
        return contextBuilder.toString();
    }
    
    
    private String generateMethodInfo(ConditionTemplateContext context, String resourceIdentifier, String methodInfo, List<Document> ragDocuments) {
        log.info("AI 특화 조건 생성 methodInfo 생성: {}", resourceIdentifier);

        
        MethodSignature signature = parseMethodSignature(resourceIdentifier);

        
        log.warn("DEBUG - 파싱 결과: resourceIdentifier={}, methodName={}, parameterInfo='{}', resourceType={}", 
                 resourceIdentifier, signature.methodName, signature.parameterInfo, signature.resourceType);
        
        
        List<Document> methodConditions = List.of();
        try {
            methodConditions = vectorService.findMethodConditions(signature.methodName, 3);
            log.debug("VectorService에서 {}개의 관련 메서드 조건 발견", methodConditions.size());
        } catch (Exception e) {
            log.warn("VectorService 메서드 조건 검색 실패: {}", e.getMessage());
        }

        
        if (signature.parameterInfo == null || signature.parameterInfo.trim().isEmpty()) {
            log.warn("파라미터 없는 메서드 감지 - 조건 생성 건너뛰기: {} - {}", signature.methodName, resourceIdentifier);
            
            context.putTemplateMetadata("skipGeneration", true);
            context.putTemplateMetadata("skipReason", "NO_PARAMETERS");
            log.warn("Context에 skipGeneration=true 설정 완료");
            return "파라미터가 없는 메서드입니다.";
        }

        
        boolean isObjectParam = signature.parameterInfo.contains("객체") ||
                signature.parameterInfo.contains("#group") ||
                signature.parameterInfo.contains("#userDto");

        String generatedMethodInfo;
        if (isObjectParam) {
            
            generatedMethodInfo = String.format("""
                극도로 제한된 조건 생성 요청 🚨
                
                분석 대상 메서드:
                - 서비스: %s 
                - 메서드명: %s
                - 허용된 파라미터: %s (이것만 사용 가능!)
                - 리소스 타입: %s (참고용, hasPermission에서 사용 금지!)
                
                hasPermission 사용법:
                %s
                
                메서드 컨텍스트:
                %s
                
                시스템 크래시 방지 규칙:
                1. 정확히 하나의 조건만 생성 (2개 이상 시 시스템 오류)
                2. 위에 명시된 파라미터만 사용 (다른 파라미터 시 크래시)
                3. hasPermission()은 반드시 2개 파라미터만 사용 (3개 파라미터 시 크래시)
                4. 리소스 타입을 hasPermission에 절대 사용하지 마세요! (크래시!)
                5. "~대상 검증", "~접근 확인" 용어만 사용 ("~권한" 시 크래시)
                6. hasPermission() 함수만 사용 (다른 함수 시 크래시)
                
                시스템 크래시 유발 항목:
                - #currentUser, #user, #rootScope (절대 존재하지 않음)
                - hasPermission(#userDto, 'USER', 'UPDATE') 형식 (크래시!)
                - hasPermission(#document, 'DOCUMENT', 'CREATE') 형식 (크래시!)
                - hasPermission(#group, 'GROUP', 'UPDATE') 형식 (크래시!)
                - 여러 조건 생성
                - "권한" 용어 사용 (시스템 크래시!)
                
                올바른 네이밍 예시:
                - "그룹 수정 대상 검증" (권한 X, 대상 검증 O)
                - "사용자 수정 대상 검증" (권한 X, 대상 검증 O)  
                - "문서 생성 대상 검증" (권한 X, 대상 검증 O)
                - "그룹 생성 접근 확인" (권한 X, 접근 확인 O)
                
                올바른 SpEL 예시:
                - hasPermission(#document, 'CREATE') ← 2개 파라미터만!
                - hasPermission(#userDto, 'UPDATE') ← 2개 파라미터만!
                - hasPermission(#group, 'UPDATE') ← 2개 파라미터만!
                """,
                    getServiceName(signature.resourceType),
                    signature.methodName,
                    signature.parameterInfo,
                    signature.resourceType,
                    generateHasPermissionUsage(signature),
                    getMethodContext(signature.methodName));
        } else {
            
            generatedMethodInfo = String.format("""
                극도로 제한된 조건 생성 요청 🚨
                
                분석 대상 메서드:
                - 서비스: %s 
                - 메서드명: %s
                - 허용된 파라미터: %s (이것만 사용 가능!)
                - 허용된 리소스 타입: %s (이것만 사용 가능!)
                
                hasPermission 사용법:
                %s
                
                메서드 컨텍스트:
                %s
                
                시스템 크래시 방지 규칙:
                1. 정확히 하나의 조건만 생성 (2개 이상 시 시스템 오류)
                2. 위에 명시된 파라미터만 사용 (다른 파라미터 시 크래시)
                3. 위에 명시된 리소스 타입만 사용 (다른 타입 시 크래시)
                4. hasPermission()은 반드시 3개 파라미터 사용 (2개 파라미터 시 크래시)
                5. "~대상 검증", "~접근 확인" 용어만 사용 ("~권한" 시 크래시)
                6. hasPermission() 함수만 사용 (다른 함수 시 크래시)
                
                시스템 크래시 유발 항목:
                - #document, #currentUser, #user (절대 존재하지 않음)
                - DOCUMENT, ROLE, SYSTEM (절대 존재하지 않음)
                - hasPermission(#id, 'READ') 형식 (2개 파라미터 크래시!)
                - 여러 조건 생성
                - "권한" 용어 사용 (시스템 크래시!)
                
                올바른 네이밍 예시:
                - "그룹 삭제 대상 검증" (권한 X, 대상 검증 O)
                - "사용자 조회 접근 확인" (권한 X, 접근 확인 O)  
                - "그룹 조회 접근 확인" (권한 X, 접근 확인 O)
                - "사용자 삭제 대상 검증" (권한 X, 대상 검증 O)
                """,
                    getServiceName(signature.resourceType),
                    signature.methodName,
                    signature.parameterInfo,
                    signature.resourceType,
                    generateHasPermissionUsage(signature),
                    getMethodContext(signature.methodName));
        }

        
        if (ragDocuments != null && !ragDocuments.isEmpty()) {
            StringBuilder enrichedInfo = new StringBuilder(generatedMethodInfo);
            enrichedInfo.append("\n\n📚 RAG 기반 유사 템플릿 예시:\n");
            for (int i = 0; i < Math.min(2, ragDocuments.size()); i++) {
                Document doc = ragDocuments.get(i);
                enrichedInfo.append("- ").append(doc.getText().substring(0, Math.min(150, doc.getText().length())));
                if (doc.getText().length() > 150) {
                    enrichedInfo.append("...");
                }
                enrichedInfo.append("\n");
            }
            generatedMethodInfo = enrichedInfo.toString();
        }
        
        log.debug("생성된 methodInfo: {}", generatedMethodInfo);
        return generatedMethodInfo;
    }
    
    
    private String getDefaultContext() {
        return """
        ## 기본 조건 템플릿 컨텍스트
        
        ### 기본 지침
        - Spring Security 표준 표현식 사용
        - hasPermission() 함수 중심 활용
        - 간단하고 명확한 조건 생성
        - "권한" 용어 사용 금지
        
        ### 기본 패턴
        - 인증 확인: isAuthenticated()
        - 역할 확인: hasRole('ROLE_ADMIN')
        - 리소스 접근: hasPermission(#param, 'ACTION')
        """;
    }
    
    
    
    
    
    
    private MethodSignature parseMethodSignature(String resourceIdentifier) {
        log.warn("DEBUG - 메서드 시그니처 파싱 시작: {}", resourceIdentifier);

        try {
            
            int lastDotIndex = resourceIdentifier.lastIndexOf('.');
            if (lastDotIndex == -1) {
                throw new IllegalArgumentException("잘못된 resource_identifier 형태: " + resourceIdentifier);
            }

            String className = resourceIdentifier.substring(0, lastDotIndex);
            String methodPart = resourceIdentifier.substring(lastDotIndex + 1);
            log.warn("DEBUG - className: {}, methodPart: {}", className, methodPart);

            
            String methodName;
            String paramTypes = "";

            if (methodPart.contains("(")) {
                methodName = methodPart.substring(0, methodPart.indexOf("("));
                String paramPart = methodPart.substring(methodPart.indexOf("(") + 1, methodPart.lastIndexOf(")"));
                paramTypes = paramPart.trim();
                log.warn("DEBUG - methodName: {}, paramPart: '{}', paramTypes: '{}'", methodName, paramPart, paramTypes);
            } else {
                methodName = methodPart;
                log.warn("DEBUG - methodName: {} (괄호 없음)", methodName);
            }

            
            String resourceType = determineResourceTypeFromClassName(className);

            
            String parameterInfo = parseParameterInfo(methodName, paramTypes);

            log.debug("파싱 결과 - 메서드: {}, 파라미터: {}, 리소스타입: {}",
                    methodName, parameterInfo, resourceType);

            return new MethodSignature(methodName, parameterInfo, resourceType);

        } catch (Exception e) {
            log.error("메서드 시그니처 파싱 실패: {}", resourceIdentifier, e);
            
            return new MethodSignature(
                    extractMethodName(resourceIdentifier),
                    null, 
                    "UNKNOWN"
            );
        }
    }
    
    
    private String determineResourceTypeFromClassName(String className) {
        String simpleName = className.substring(className.lastIndexOf('.') + 1);

        
        if (simpleName.contains("Group")) {
            return "GROUP";
        } else if (simpleName.contains("User")) {
            return "USER";
        } else if (simpleName.contains("Role")) {
            return "ROLE";
        } else if (simpleName.contains("Permission")) {
            return "PERMISSION";
        } else if (simpleName.contains("Document")) {
            return "DOCUMENT";
        } else if (simpleName.contains("Policy")) {
            return "POLICY";
        } else {
            
            String resourceName = simpleName.replace("Service", "").replace("Impl", "");
            return resourceName.toUpperCase();
        }
    }
    
    
    private String parseParameterInfo(String methodName, String paramTypes) {
        log.warn("DEBUG - parseParameterInfo: methodName={}, paramTypes='{}'", methodName, paramTypes);
        
        if (paramTypes == null || paramTypes.trim().isEmpty() || paramTypes.equals("없음") || paramTypes.equals("()")) {
            log.warn("DEBUG - 파라미터 없음으로 판단: paramTypes='{}'", paramTypes);
            return null; 
        }

        
        String result = parseParameterTypesFromString(paramTypes);
        log.warn("DEBUG - parseParameterInfo 결과: '{}'", result);
        return result;
    }
    
    
    private String parseParameterTypesFromString(String paramTypes) {
        if (paramTypes == null || paramTypes.trim().isEmpty()) {
            return null; 
        }

        
        String cleanTypes = paramTypes.replaceAll("[()]", "").trim();
        if (cleanTypes.isEmpty()) {
            return null; 
        }

        
        String[] types = cleanTypes.split(",");
        List<String> parameterInfos = new ArrayList<>();

        for (int i = 0; i < types.length; i++) {
            String type = types[i].trim();
            String paramInfo = generateParameterInfo(type, i);
            parameterInfos.add(paramInfo);
        }

        return String.join(", ", parameterInfos);
    }
    
    
    private String generateParameterInfo(String type, int index) {
        
        String baseType = type.contains("<") ? type.substring(0, type.indexOf("<")) : type;

        
        if (baseType.contains(".")) {
            baseType = baseType.substring(baseType.lastIndexOf(".") + 1);
        }

        
        String paramName = generateParameterName(baseType, index);
        String typeDescription = generateTypeDescription(type);

        return String.format("#%s (%s)", paramName, typeDescription);
    }
    
    
    private String generateParameterName(String type, int index) {
        
        if (type.startsWith("List<")) {
            if (type.contains("Long")) {
                return "selectedRoleIds"; 
            } else if (type.contains("String")) {
                return "selectedItems";
            } else {
                return "list" + (index == 0 ? "" : index);
            }
        }

        switch (type) {
            
            case "Long":
            case "Integer":
            case "int":
            case "long":
                return index == 0 ? "id" : (index == 1 ? "idx" : "param" + index);
            case "String":
                return index == 0 ? "value" : "param" + index;
            case "Boolean":
            case "boolean":
                return index == 0 ? "flag" : "param" + index;

            
            case "Group":
                return "group";
            case "User":
                return "user";
            case "UserDto":
                return "userDto";
            case "UserListDto":
                return "userListDto";
            case "Role":
                return "role";
            case "Permission":
                return "permission";
            case "Document":
                return "document";

            
            case "List":
                return "selectedRoleIds"; 
            case "Set":
                return index == 0 ? "set" : "set" + index;
            case "Map":
                return index == 0 ? "map" : "map" + index;

            
            default:
                
                String camelCase = type.substring(0, 1).toLowerCase() + type.substring(1);
                return camelCase;
        }
    }
    
    
    private String generateTypeDescription(String fullType) {
        if (fullType.contains("<")) {
            
            return fullType + " 타입";
        } else {
            
            String baseType = fullType.contains(".") ?
                    fullType.substring(fullType.lastIndexOf(".") + 1) : fullType;

            
            switch (baseType) {
                case "Long":
                case "Integer":
                case "String":
                case "Boolean":
                case "int":
                case "long":
                case "boolean":
                    return baseType + " 타입";
                default:
                    return baseType + " 객체";
            }
        }
    }
    
    
    private String getServiceName(String resourceType) {
        if (resourceType == null || resourceType.equals("UNKNOWN")) {
            return "Unknown Service";
        }

        
        String serviceName = resourceType.toLowerCase();
        serviceName = serviceName.substring(0, 1).toUpperCase() + serviceName.substring(1);
        return serviceName + "Service";
    }
    
    
    private String getMethodContext(String methodName) {
        if (methodName == null) {
            return "메서드 정보가 없습니다.";
        }

        
        String action = determineMethodAction(methodName);
        String entity = determineMethodEntity(methodName);

        return String.format("%s %s 메서드입니다.", entity, action);
    }
    
    
    private String determineMethodAction(String methodName) {
        String lowerName = methodName.toLowerCase();

        if (lowerName.startsWith("create") || lowerName.startsWith("add") ||
                lowerName.startsWith("insert") || lowerName.startsWith("new") ||
                lowerName.startsWith("register") || lowerName.startsWith("build")) {
            return "생성하는";
        } else if (lowerName.startsWith("get") || lowerName.startsWith("find") ||
                lowerName.startsWith("fetch") || lowerName.startsWith("retrieve") ||
                lowerName.startsWith("select") || lowerName.startsWith("search") ||
                lowerName.startsWith("load") || lowerName.startsWith("read") ||
                lowerName.startsWith("view") || lowerName.startsWith("show")) {
            return "조회하는";
        } else if (lowerName.startsWith("update") || lowerName.startsWith("modify") ||
                lowerName.startsWith("edit") || lowerName.startsWith("change") ||
                lowerName.startsWith("alter") || lowerName.startsWith("set")) {
            return "수정하는";
        } else if (lowerName.startsWith("delete") || lowerName.startsWith("remove") ||
                lowerName.startsWith("drop") || lowerName.startsWith("clear") ||
                lowerName.startsWith("destroy") || lowerName.startsWith("purge")) {
            return "삭제하는";
        } else if (lowerName.startsWith("save") || lowerName.startsWith("store") ||
                lowerName.startsWith("persist")) {
            return "저장하는";
        } else if (lowerName.startsWith("validate") || lowerName.startsWith("check")) {
            return "검증하는";
        } else {
            return "처리하는";
        }
    }
    
    
    private String determineMethodEntity(String methodName) {
        String lowerName = methodName.toLowerCase();

        if (lowerName.contains("group")) {
            return "그룹을";
        } else if (lowerName.contains("user")) {
            return "사용자를";
        } else if (lowerName.contains("role")) {
            return "역할을";
        } else if (lowerName.contains("permission")) {
            return "권한을";
        } else if (lowerName.contains("document")) {
            return "문서를";
        } else if (lowerName.contains("policy")) {
            return "정책을";
        } else {
            return "리소스를";
        }
    }
    
    
    private String generateHasPermissionUsage(MethodSignature signature) {
        
        String paramInfo = signature.parameterInfo.toLowerCase();
        
        
        String action = extractActionFromMethod(signature.methodName).toUpperCase();
        String actionType = determineActionType(signature.methodName);

        if (paramInfo.contains("#id (long") || paramInfo.contains("#idx (long")) {
            
            String paramName = paramInfo.contains("#idx") ? "#idx" : "#id";
            return String.format("올바른 형식: hasPermission(%s, '%s', '%s') - ID는 반드시 3개 파라미터",
                    paramName, signature.resourceType, actionType);
        } else if (paramInfo.contains("객체") || paramInfo.contains("#group") || paramInfo.contains("#userDto")) {
            
            String paramName = extractParamName(signature.parameterInfo);
            String objectAction = signature.resourceType + "_" + actionType;
            return String.format("올바른 형식: hasPermission(%s, '%s') - 객체는 반드시 2개 파라미터만! 리소스 타입 사용 금지!",
                    paramName, objectAction);
        } else if (paramInfo.contains("#selectedRoleIds")) {
            
            return "List 파라미터는 hasPermission에서 직접 사용하지 않음";
        } else {
            return "hasPermission() 형식을 정확히 사용하세요";
        }
    }
    
    
    private String determineActionType(String methodName) {
        if (methodName == null || methodName.trim().isEmpty()) {
            return "UPDATE";
        }

        String lowerMethod = methodName.toLowerCase().trim();

        if (lowerMethod.startsWith("create") || lowerMethod.startsWith("add") ||
                lowerMethod.startsWith("insert") || lowerMethod.startsWith("new") ||
                lowerMethod.startsWith("register") || lowerMethod.startsWith("build")) {
            return "CREATE";
        } else if (lowerMethod.startsWith("get") || lowerMethod.startsWith("find") ||
                lowerMethod.startsWith("fetch") || lowerMethod.startsWith("retrieve") ||
                lowerMethod.startsWith("select") || lowerMethod.startsWith("search") ||
                lowerMethod.startsWith("load") || lowerMethod.startsWith("read") ||
                lowerMethod.startsWith("view") || lowerMethod.startsWith("show")) {
            return "READ";
        } else if (lowerMethod.startsWith("update") || lowerMethod.startsWith("modify") ||
                lowerMethod.startsWith("edit") || lowerMethod.startsWith("change") ||
                lowerMethod.startsWith("alter") || lowerMethod.startsWith("set")) {
            return "UPDATE";
        } else if (lowerMethod.startsWith("delete") || lowerMethod.startsWith("remove") ||
                lowerMethod.startsWith("drop") || lowerMethod.startsWith("clear") ||
                lowerMethod.startsWith("destroy") || lowerMethod.startsWith("purge")) {
            return "DELETE";
        } else {
            return "UPDATE"; 
        }
    }
    
    
    private String extractParamName(String parameterInfo) {
        if (parameterInfo.contains("#group")) {
            return "#group";
        } else if (parameterInfo.contains("#userDto")) {
            return "#userDto";
        } else if (parameterInfo.contains("#id")) {
            return "#id";
        } else if (parameterInfo.contains("#idx")) {
            return "#idx";
        } else {
            return "#param";
        }
    }
    
    
    private String extractMethodName(String resourceIdentifier) {
        if (resourceIdentifier == null || resourceIdentifier.trim().isEmpty()) {
            return "unknown";
        }
        
        
        int lastDotIndex = resourceIdentifier.lastIndexOf('.');
        if (lastDotIndex == -1) {
            return resourceIdentifier;
        }
        
        String methodPart = resourceIdentifier.substring(lastDotIndex + 1);
        
        
        if (methodPart.contains("(")) {
            return methodPart.substring(0, methodPart.indexOf("("));
        }
        
        return methodPart;
    }

    
    private String extractMethodNameFromSignature(String methodSignature) {
        if (methodSignature == null || methodSignature.trim().isEmpty()) {
            return "unknown";
        }

        String trimmed = methodSignature.trim();

        
        int parenIndex = trimmed.indexOf('(');
        if (parenIndex != -1) {
            return trimmed.substring(0, parenIndex).trim();
        }

        
        return trimmed;
    }

    
    private String extractActionFromMethod(String methodName) {
        if (methodName == null || methodName.trim().isEmpty()) {
            return "처리";
        }

        String lowerMethod = methodName.toLowerCase().trim();

        
        if (lowerMethod.startsWith("create") || lowerMethod.startsWith("add") ||
                lowerMethod.startsWith("insert") || lowerMethod.startsWith("new") ||
                lowerMethod.startsWith("register") || lowerMethod.startsWith("build")) {
            return "생성";
        } else if (lowerMethod.startsWith("get") || lowerMethod.startsWith("find") ||
                lowerMethod.startsWith("fetch") || lowerMethod.startsWith("retrieve") ||
                lowerMethod.startsWith("select") || lowerMethod.startsWith("search") ||
                lowerMethod.startsWith("load") || lowerMethod.startsWith("read") ||
                lowerMethod.startsWith("view") || lowerMethod.startsWith("show")) {
            return "조회";
        } else if (lowerMethod.startsWith("update") || lowerMethod.startsWith("modify") ||
                lowerMethod.startsWith("edit") || lowerMethod.startsWith("change") ||
                lowerMethod.startsWith("alter") || lowerMethod.startsWith("set")) {
            return "수정";
        } else if (lowerMethod.startsWith("delete") || lowerMethod.startsWith("remove") ||
                lowerMethod.startsWith("drop") || lowerMethod.startsWith("clear") ||
                lowerMethod.startsWith("destroy") || lowerMethod.startsWith("purge")) {
            return "삭제";
        } else if (lowerMethod.startsWith("save") || lowerMethod.startsWith("store") ||
                lowerMethod.startsWith("persist")) {
            return "저장";
        } else if (lowerMethod.startsWith("validate") || lowerMethod.startsWith("check") ||
                lowerMethod.startsWith("verify") || lowerMethod.startsWith("confirm")) {
            return "검증";
        } else if (lowerMethod.startsWith("approve") || lowerMethod.startsWith("accept")) {
            return "승인";
        } else if (lowerMethod.startsWith("reject") || lowerMethod.startsWith("deny") ||
                lowerMethod.startsWith("decline")) {
            return "거부";
        } else if (lowerMethod.startsWith("assign") || lowerMethod.startsWith("grant") ||
                lowerMethod.startsWith("give") || lowerMethod.startsWith("allocate")) {
            return "할당";
        } else if (lowerMethod.startsWith("revoke") || lowerMethod.startsWith("unassign") ||
                lowerMethod.startsWith("withdraw") || lowerMethod.startsWith("cancel")) {
            return "취소";
        } else if (lowerMethod.startsWith("send") || lowerMethod.startsWith("notify") ||
                lowerMethod.startsWith("alert")) {
            return "전송";
        } else if (lowerMethod.startsWith("process") || lowerMethod.startsWith("handle") ||
                lowerMethod.startsWith("execute") || lowerMethod.startsWith("run")) {
            return "처리";
        } else if (lowerMethod.startsWith("count") || lowerMethod.startsWith("calculate") ||
                lowerMethod.startsWith("compute")) {
            return "계산";
        } else if (lowerMethod.startsWith("copy") || lowerMethod.startsWith("clone") ||
                lowerMethod.startsWith("duplicate")) {
            return "복사";
        } else if (lowerMethod.startsWith("move") || lowerMethod.startsWith("transfer")) {
            return "이동";
        } else if (lowerMethod.startsWith("export") || lowerMethod.startsWith("download")) {
            return "내보내기";
        } else if (lowerMethod.startsWith("import") || lowerMethod.startsWith("upload")) {
            return "가져오기";
        } else {
            
            return "처리";
        }
    }

    
    private String getKoreanEntityName(String entityType) {
        if (entityType == null || entityType.trim().isEmpty()) {
            return "리소스";
        }

        
        String normalizedType = entityType.trim();
        String lowerType = normalizedType.toLowerCase();

        
        if (lowerType.contains("user")) {
            return "사용자";
        } else if (lowerType.contains("group")) {
            return "그룹";
        } else if (lowerType.contains("role")) {
            return "역할";
        } else if (lowerType.contains("permission")) {
            return "권한";
        } else if (lowerType.contains("policy")) {
            return "정책";
        } else if (lowerType.contains("document")) {
            return "문서";
        } else if (lowerType.contains("file")) {
            return "파일";
        } else if (lowerType.contains("project")) {
            return "프로젝트";
        } else if (lowerType.contains("organization") || lowerType.contains("org")) {
            return "조직";
        } else if (lowerType.contains("department") || lowerType.contains("dept")) {
            return "부서";
        } else if (lowerType.contains("team")) {
            return "팀";
        } else if (lowerType.contains("resource")) {
            return "리소스";
        } else if (lowerType.contains("data")) {
            return "데이터";
        } else if (lowerType.contains("system")) {
            return "시스템";
        } else if (lowerType.contains("service")) {
            return "서비스";
        } else {
            
            return normalizedType.substring(0, 1).toLowerCase() + normalizedType.substring(1);
        }
    }

    
    private String generateMethodSuffix(String methodId) {
        
        if (methodId == null) return "AUTO";

        String[] parts = methodId.split("\\.");
        if (parts.length >= 2) {
            String className = parts[parts.length - 2];
            String methodName = parts[parts.length - 1];

            
            String classPrefix = className.length() > 0 ? className.substring(0, 1).toUpperCase() : "X";
            String methodPrefix = methodName.length() >= 3 ? methodName.substring(0, 3).toUpperCase() : methodName.toUpperCase();

            return classPrefix + methodPrefix;
        }

        
        return String.valueOf(Math.abs(methodId.hashCode()) % 10000);
    }
    
    
    private static class TemplateQueryTransformer implements QueryTransformer {
        private final ChatClient chatClient;
        
        public TemplateQueryTransformer(ChatClient.Builder chatClientBuilder) {
            this.chatClient = chatClientBuilder.build();
        }
        
        @Override
        public Query transform(Query originalQuery) {
            if (originalQuery == null || originalQuery.text() == null) {
                return originalQuery;
            }
            
            String prompt = String.format("""
                조건 템플릿 검색을 위한 쿼리를 최적화하세요:
                
                원본 쿼리: %s
                
                최적화 지침:
                1. Spring Security SpEL 표현식 관련 용어를 포함하세요
                2. hasPermission, hasRole, hasAuthority 같은 메서드명을 추가하세요
                3. RBAC, ABAC 패턴 관련 키워드를 포함하세요
                4. 리소스 타입과 액션 타입을 구체화하세요
                5. 조건 템플릿 패턴과 관련된 용어를 추가하세요
                
                최적화된 쿼리만 반환하세요.
                """, originalQuery.text());
            
            String transformedText = chatClient.prompt()
                .user(prompt)
                .call()
                .content();
                
            return new Query(transformedText);
        }
    }
} 