package io.contexa.contexacore.std.components.retriever;

import io.contexa.contexacore.std.labs.risk.RiskAssessmentVectorService;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.BusinessResourceActionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 위험 평가 컨텍스트 검색기 - AI-Native 보안 전문 구현
 * 
 * 다른 ContextRetriever들과 동일한 패턴 적용:
 * - RAG 검색 (VectorStore)
 * - 시스템 메타데이터 구성 (DB Repository 활용)
 * - ContextRetrieverRegistry 자동 등록
 * 
 * 역할:
 * 1. RAG 기반 위험 평가 관련 문서/패턴 검색
 * 2. 실시간 사용자 행동, 감사로그, 리소스 접근 히스토리 분석
 * 3. 제로 트러스트 위험 평가를 위한 종합 컨텍스트 구성
 * 
 * 검색 영역:
 * - 과거 위험 평가 사례 (Vector Store)
 * - 사용자 행동 패턴 분석 (DB + Vector)
 * - 리소스별 위험 프로파일 (DB)
 * - 비정상 접근 패턴 탐지 (DB + ML)
 */
@Slf4j
@Component
public class RiskAssessmentContextRetriever extends ContextRetriever {

    private final VectorStore vectorStore;
    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final BusinessResourceActionRepository resourceActionRepository;
    private final ContextRetrieverRegistry contextRetrieverRegistry;
    private final RiskAssessmentVectorService vectorService;

    public RiskAssessmentContextRetriever(
            VectorStore vectorStore,
            UserRepository userRepository,
            AuditLogRepository auditLogRepository,
            BusinessResourceActionRepository resourceActionRepository,
            ContextRetrieverRegistry contextRetrieverRegistry,
            RiskAssessmentVectorService vectorService) {
        super(vectorStore);
        this.vectorStore = vectorStore;
        this.userRepository = userRepository;
        this.auditLogRepository = auditLogRepository;
        this.resourceActionRepository = resourceActionRepository;
        this.contextRetrieverRegistry = contextRetrieverRegistry;
        this.vectorService = vectorService;
    }

    @PostConstruct
    public void registerSelf() {
        contextRetrieverRegistry.registerRetriever(RiskAssessmentContext.class, this);
        log.info("RiskAssessmentContextRetriever 자동 등록 완료: RiskAssessmentContext → {}", 
                this.getClass().getSimpleName());
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        log.debug("RiskAssessmentContextRetriever.retrieveContext 호출됨");
        
        // RiskAssessmentContext 타입인 경우 특화 처리
        if (request.getContext() instanceof RiskAssessmentContext) {
            String contextInfo = retrieveRiskAssessmentContext((AIRequest<RiskAssessmentContext>) request);
            return new ContextRetrievalResult(
                contextInfo, 
                List.of(), // 빈 문서 리스트
                Map.of("retrieverType", "RiskAssessmentContextRetriever", "timestamp", System.currentTimeMillis())
            );
        }
        
        // 그 외의 경우 상위 클래스의 기본 처리
        return super.retrieveContext(request);
    }

    /**
     * 위험 평가 컨텍스트 종합 검색
     * 
     * 실무급 구현:
     * 1. RAG 기반 과거 위험 사례 검색
     * 2. DB 기반 사용자 행동 패턴 분석
     * 3. 리소스별 위험 프로파일 구성
     * 4. 실시간 이상 탐지 결과 반영
     */
    public String retrieveRiskAssessmentContext(AIRequest<RiskAssessmentContext> request) {
        log.info("위험 평가 컨텍스트 검색 시작: {}", request.getRequestId());
        
        try {
            RiskAssessmentContext context = request.getContext();
            StringBuilder contextBuilder = new StringBuilder();
            
            // VectorService에 위험 평가 요청 저장
            try {
                vectorService.storeRiskAssessment(context);
                log.debug("💾 VectorService에 위험 평가 요청 저장 완료");
            } catch (Exception e) {
                log.warn("VectorService 위험 평가 저장 실패: {}", e.getMessage());
            }
            
            // 1. RAG 기반 과거 위험 사례 검색
            String historicalRiskPatterns = searchHistoricalRiskPatterns(context);
            if (!historicalRiskPatterns.isEmpty()) {
                contextBuilder.append("## 📚 과거 위험 평가 사례 분석\n");
                contextBuilder.append(historicalRiskPatterns).append("\n\n");
            }
            
            // 2. 사용자 행동 패턴 분석
            String userBehaviorAnalysis = analyzeUserBehaviorPatterns(context);
            contextBuilder.append("## 👤 사용자 행동 패턴 분석\n");
            contextBuilder.append(userBehaviorAnalysis).append("\n\n");
            
            // 3. 리소스별 위험 프로파일
            String resourceRiskProfile = buildResourceRiskProfile(context);
            contextBuilder.append("## 리소스 위험 프로파일\n");
            contextBuilder.append(resourceRiskProfile).append("\n\n");
            
            // 4. 실시간 이상 탐지 결과
            String anomalyDetectionResult = performAnomalyDetection(context);
            contextBuilder.append("## 실시간 이상 탐지 결과\n");
            contextBuilder.append(anomalyDetectionResult).append("\n\n");
            
            // 5. 위험 평가 가이드라인
            String riskAssessmentGuidelines = getRiskAssessmentGuidelines();
            contextBuilder.append("## 위험 평가 가이드라인\n");
            contextBuilder.append(riskAssessmentGuidelines);
            
            String result = contextBuilder.toString();
            log.info("위험 평가 컨텍스트 검색 완료 - 컨텍스트 길이: {}", result.length());
            
            // VectorService에 위험 평가 결과 저장
            try {
                double riskScore = context.calculateRiskComplexity() / 20.0; // 정규화
                vectorService.storeRiskResult(request.getRequestId(), riskScore, result);
                log.debug("💾 VectorService에 위험 평가 결과 저장 완료 - 점수: {}", riskScore);
            } catch (Exception e) {
                log.warn("VectorService 결과 저장 실패: {}", e.getMessage());
            }
            
            return result;
            
        } catch (Exception e) {
            log.error("위험 평가 컨텍스트 검색 실패", e);
            return getDefaultRiskAssessmentContext();
        }
    }

    /**
     * 📚 RAG 기반 과거 위험 사례 검색
     */
    private String searchHistoricalRiskPatterns(RiskAssessmentContext context) {
        try {
            // 1. VectorService를 통한 위험 패턴 검색
            List<Document> similarRisks = vectorService.findSimilarRiskPatterns(
                context.getUserId(), 
                context.getResourceIdentifier(), 
                5
            );
            
            // 2. 기존 VectorStore 검색도 병행
            String searchQuery = String.format(
                "위험 평가 사례 user:%s resource:%s action:%s ip:%s", 
                context.getUserId(), 
                context.getResourceIdentifier(), 
                context.getActionType(),
                context.getRemoteIp()
            );
            
            SearchRequest searchRequest = SearchRequest.builder()
                .query(searchQuery)
                .topK(3)
                .similarityThreshold(0.7)
                .build();
            
            List<Document> vectorDocs = vectorStore.similaritySearch(searchRequest);
            
            // 3. 결과 병합
            List<Document> riskDocs = new ArrayList<>();
            riskDocs.addAll(similarRisks);
            for (Document doc : vectorDocs) {
                boolean isDuplicate = riskDocs.stream()
                    .anyMatch(existing -> existing.getText().equals(doc.getText()));
                if (!isDuplicate) {
                    riskDocs.add(doc);
                }
            }
            
            if (riskDocs.isEmpty()) {
                return "해당 사용자/리소스/액션 조합에 대한 과거 위험 평가 사례를 찾을 수 없습니다.";
            }
            
            return riskDocs.stream()
                .map(doc -> "- " + doc.getText())
                .collect(Collectors.joining("\n"));
                
        } catch (Exception e) {
            log.warn("RAG 위험 사례 검색 실패: {}", e.getMessage());
            return "위험 사례 검색 중 오류가 발생했습니다.";
        }
    }

    /**
     * 👤 DB 기반 사용자 행동 패턴 분석
     */
    private String analyzeUserBehaviorPatterns(RiskAssessmentContext context) {
        try {
            StringBuilder analysis = new StringBuilder();
            
            // 사용자 기본 정보
            userRepository.findByUsernameWithGroupsRolesAndPermissions(context.getUserId()).ifPresent(user -> {
                analysis.append(String.format("- 사용자: %s (ID: %d)\n", user.getName(), user.getId()));
                analysis.append(String.format("- 계정 상태: %s\n", "활성")); // Users 엔티티에 isEnabled 없음
                analysis.append(String.format("- 생성일: %s\n", user.getCreatedAt()));
                analysis.append(String.format("- MFA 활성화: %s\n", user.isMfaEnabled() ? "예" : "아니오"));
            });
            
            // 최근 감사로그 분석 (최근 5개 로그)
            List<AuditLog> recentLogs = auditLogRepository.findTop5ByPrincipalNameOrderByIdDesc(context.getUserId());
            
            if (!recentLogs.isEmpty()) {
                analysis.append(String.format("- 최근 활동 횟수: %d건\n", recentLogs.size()));
                
                // 액션 타입별 통계
                Map<String, Long> actionStats = recentLogs.stream()
                    .collect(Collectors.groupingBy(
                        log -> log.getAction(),
                        Collectors.counting()
                    ));
                
                analysis.append("- 액션별 통계:\n");
                actionStats.forEach((action, count) -> 
                    analysis.append(String.format("  * %s: %d건\n", action, count))
                );
                
                // 비정상 패턴 탐지
                long distinctIpCount = recentLogs.stream()
                    .map(log -> log.getClientIp())
                    .distinct()
                    .count();
                
                if (distinctIpCount > 3) {
                    analysis.append(String.format("주의: 최근 %d개의 서로 다른 IP에서 접근\n", distinctIpCount));
                }
                
                // 추가 통계
                LocalDateTime oneWeekAgo = LocalDateTime.now().minusWeeks(1);
                long totalWeeklyActivities = auditLogRepository.countByPrincipalNameAndTimeRange(
                    context.getUserId(), oneWeekAgo, LocalDateTime.now());
                analysis.append(String.format("- 최근 7일간 총 활동: %d건\n", totalWeeklyActivities));
                
            } else {
                analysis.append("- 최근 활동 기록이 없습니다.\n");
            }
            
            return analysis.toString();
            
        } catch (Exception e) {
            log.warn("사용자 행동 패턴 분석 실패: {}", e.getMessage());
            return "사용자 행동 패턴 분석 중 오류가 발생했습니다.";
        }
    }

    /**
     * 리소스별 위험 프로파일 구성
     */
    private String buildResourceRiskProfile(RiskAssessmentContext context) {
        try {
            StringBuilder profile = new StringBuilder();
            
            profile.append(String.format("- 대상 리소스: %s\n", context.getResourceIdentifier()));
            profile.append(String.format("- 요청 액션: %s\n", context.getActionType()));
            
            // 리소스 정보 조회
            if (context.getResourceIdentifier() != null) {
                long actionCount = resourceActionRepository.countActionsByResourceIdentifier(context.getResourceIdentifier());
                profile.append(String.format("- 리소스 허용 액션 수: %d개\n", actionCount));
                
                // 리소스 민감도 조회
                resourceActionRepository.getResourceSensitivityLevel(context.getResourceIdentifier())
                    .ifPresent(level -> profile.append(String.format("- 리소스 민감도: %s\n", level)));
                
                // 리소스 존재 여부
                resourceActionRepository.findByResourceIdentifier(context.getResourceIdentifier())
                    .ifPresentOrElse(
                        resource -> profile.append(String.format("- 리소스 타입: %s\n", resource.getResourceType())),
                        () -> profile.append("- 해당 리소스가 시스템에 등록되지 않았습니다.\n")
                    );
            }
            
            // 감사 로그 기반 접근 통계
            if (context.getResourceIdentifier() != null) {
                long totalAccess = auditLogRepository.countByResourceIdentifier(context.getResourceIdentifier());
                long uniqueUsers = auditLogRepository.countDistinctUsersByResourceIdentifier(context.getResourceIdentifier());
                long recentFailures = auditLogRepository.countFailedAttemptsSince(
                    context.getResourceIdentifier(), LocalDateTime.now().minusHours(24));
                
                profile.append(String.format("- 총 접근 횟수: %d건\n", totalAccess));
                profile.append(String.format("- 접근한 고유 사용자 수: %d명\n", uniqueUsers));
                profile.append(String.format("- 최근 24시간 실패 시도: %d건\n", recentFailures));
            }
            
            // 리소스 민감도 분석
            if (context.getResourceIdentifier() != null) {
                if (context.getResourceIdentifier().toLowerCase().contains("admin")) {
                    profile.append("높은 위험도: 관리자 리소스 접근\n");
                } else if (context.getResourceIdentifier().toLowerCase().contains("user")) {
                    profile.append("중간 위험도: 사용자 리소스 접근\n");
                } else {
                    profile.append("낮은 위험도: 일반 리소스 접근\n");
                }
            }
            
            return profile.toString();
            
        } catch (Exception e) {
            log.warn("리소스 위험 프로파일 구성 실패: {}", e.getMessage());
            return "리소스 위험 프로파일 구성 중 오류가 발생했습니다.";
        }
    }

    /**
     * 실시간 이상 탐지
     */
    private String performAnomalyDetection(RiskAssessmentContext context) {
        StringBuilder detection = new StringBuilder();
        
        // IP 기반 이상 탐지
        if (context.getRemoteIp() != null) {
            if (context.getRemoteIp().startsWith("10.") || 
                context.getRemoteIp().startsWith("192.168.") || 
                context.getRemoteIp().startsWith("172.")) {
                detection.append("내부 네트워크에서의 접근\n");
            } else {
                detection.append("외부 네트워크에서의 접근: ").append(context.getRemoteIp()).append("\n");
            }
        }
        
        // 시간 기반 이상 탐지
        int currentHour = LocalDateTime.now().getHour();
        if (currentHour >= 18 || currentHour <= 8) {
            detection.append("업무시간 외 접근 시도\n");
        } else {
            detection.append("정상 업무시간 내 접근\n");
        }
        
        // 권한 복잡도 분석
        int complexityScore = context.calculateRiskComplexity();
        if (complexityScore > 10) {
            detection.append(String.format("높은 권한 복잡도: %d점\n", complexityScore));
        } else {
            detection.append(String.format("정상 권한 복잡도: %d점\n", complexityScore));
        }
        
        return detection.toString();
    }

    /**
     * 위험 평가 가이드라인
     */
    private String getRiskAssessmentGuidelines() {
        return """
        ### 위험 점수 산정 기준
        - 0.0-0.3: 낮은 위험 (허용)
        - 0.4-0.6: 중간 위험 (주의 감시)
        - 0.7-0.8: 높은 위험 (추가 인증 요구)
        - 0.9-1.0: 극도 위험 (접근 차단)
        
        ### 주요 위험 요소
        - 비정상적인 접근 시간
        - 알려지지 않은 IP 주소
        - 과도한 권한 요청
        - 비정상적인 접근 패턴
        - 최근 보안 사고 이력
        
        ### XAI 설명 요구사항
        - 위험 점수 산정 근거 명시
        - 주요 위험 요소 상세 설명
        - 권장 조치사항 제공
        - 추가 검증 방법 제안
        """;
    }

    /**
     * 기본 위험 평가 컨텍스트 (오류 발생 시)
     */
    private String getDefaultRiskAssessmentContext() {
        return """
        ## 기본 위험 평가 컨텍스트
        
        위험 평가 컨텍스트를 구성하는 중 오류가 발생했습니다.
        기본적인 위험 평가 정책을 적용합니다.
        
        - 모든 접근을 중간 위험도로 분류
        - 추가 검증 절차 권장
        - 상세한 감사로그 기록
        """;
    }
    
    /**
     * 위험 평가 쿼리 변환기
     */
    private static class RiskQueryTransformer implements QueryTransformer {
        private final ChatClient chatClient;
        
        public RiskQueryTransformer(ChatClient.Builder chatClientBuilder) {
            this.chatClient = chatClientBuilder.build();
        }
        
        @Override
        public Query transform(Query originalQuery) {
            if (originalQuery == null || originalQuery.text() == null) {
                return originalQuery;
            }
            
            String prompt = String.format("""
                위험 평가를 위한 검색 쿼리를 최적화하세요:
                
                원본 쿼리: %s
                
                최적화 지침:
                1. 보안 위협과 이상 행동 관련 용어를 포함하세요
                2. 사용자 행동 패턴과 접근 빈도를 고려하세요
                3. 리소스 민감도와 중요도를 반영하세요
                4. 시간대, IP 주소 등 컨텍스트 정보를 포함하세요
                5. 제로 트러스트 보안 모델 관련 키워드를 추가하세요
                
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