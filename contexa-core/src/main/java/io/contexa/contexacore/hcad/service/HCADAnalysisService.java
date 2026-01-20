package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import jakarta.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;


@Slf4j
public class HCADAnalysisService {

    private final HCADContextExtractor contextExtractor;
    private RedisTemplate<String, Object> redisTemplate;

    
    @Value("${hcad.analysis.max-age-ms:3600000}")
    private long analysisMaxAgeMs;

    
    
    

    public HCADAnalysisService(HCADContextExtractor contextExtractor) {
        this.contextExtractor = contextExtractor;
    }

    @Autowired
    public void setRedisTemplate(@Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    
    public HCADAnalysisResult analyze(HttpServletRequest request, Authentication authentication) {
        long startTime = System.currentTimeMillis();

        try {
            
            HCADContext context = contextExtractor.extractContext(request, authentication);
            String userId = context.getUserId();

            if (log.isDebugEnabled()) {
                log.debug("[HCADAnalysisService][AI Native] 컨텍스트 추출 완료: userId={}, path={}, ip={}",
                    userId, context.getRequestPath(), context.getRemoteIp());
            }

            
            
            Map<String, Object> llmAnalysis = getLLMAnalysisFromRedis(userId);

            
            double riskScore = (double) llmAnalysis.getOrDefault("riskScore", 0.0);
            boolean isAnomaly = (boolean) llmAnalysis.getOrDefault("isAnomaly", false);
            double anomalyScore = riskScore;
            
            double trustScore = (double) llmAnalysis.getOrDefault("trustScore", 1.0);

            
            String threatType = (String) llmAnalysis.getOrDefault("threatType", "NONE");
            String threatEvidence = (String) llmAnalysis.getOrDefault("threatEvidence", "");

            
            
            String action = (String) llmAnalysis.get("action");  
            double confidence = (double) llmAnalysis.getOrDefault("confidence", Double.NaN);

            long processingTime = System.currentTimeMillis() - startTime;

            if (log.isDebugEnabled()) {
                log.debug("[HCADAnalysisService][AI Native] 분석 완료: userId={}, action={}, riskScore={}, isAnomaly={}, confidence={}, time={}ms",
                    userId,
                    action,
                    String.format("%.3f", riskScore),
                    isAnomaly,
                    String.format("%.3f", confidence),
                    processingTime);
            }

            
            return HCADAnalysisResult.builder()
                .userId(userId)
                .trustScore(trustScore)
                .threatType(threatType)
                .threatEvidence(threatEvidence)
                .isAnomaly(isAnomaly)
                .anomalyScore(anomalyScore)
                .action(action)  
                .confidence(confidence)  
                
                .processingTimeMs(processingTime)
                .context(context)
                .build();

        } catch (Exception e) {
            log.error("[HCADAnalysisService][AI Native] 분석 실패: request={}", request.getRequestURI(), e);

            
            
            
            HCADContext errorContext = new HCADContext();
            errorContext.setIsNewSession(true);      
            errorContext.setNewUser(true);           
            errorContext.setIsNewDevice(true);       
            errorContext.setRecentRequestCount(0);   

            
            
            
            return HCADAnalysisResult.builder()
                .userId("error")
                .trustScore(Double.NaN)
                .threatType("ANALYSIS_ERROR")
                .threatEvidence("LLM 분석 조회 실패: " + e.getMessage())
                .isAnomaly(false) 
                .anomalyScore(Double.NaN)
                .action(null)  
                .confidence(Double.NaN)
                
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .context(errorContext)  
                .build();
        }
    }

    
    @SuppressWarnings("unchecked")
    private Map<String, Object> getLLMAnalysisFromRedis(String userId) {
        Map<String, Object> result = new HashMap<>();

        
        
        result.put("riskScore", Double.NaN);
        result.put("isAnomaly", false);  
        result.put("trustScore", Double.NaN);  
        result.put("threatType", "NOT_ANALYZED");
        result.put("threatEvidence", "LLM analysis not yet performed for this user");
        
        
        result.put("confidence", Double.NaN);  

        if (redisTemplate == null) {
            log.warn("[HCADAnalysisService][AI Native] RedisTemplate이 null입니다. 기본값 반환");
            return result;
        }

        try {
            
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Map<Object, Object> analysis = redisTemplate.opsForHash().entries(analysisKey);

            if (analysis != null && !analysis.isEmpty()) {
                
                boolean isStale = false;
                if (analysis.containsKey("analyzedAt")) {
                    long analyzedAt = parseLong(analysis.get("analyzedAt"));
                    long ageMs = System.currentTimeMillis() - analyzedAt;
                    if (ageMs > analysisMaxAgeMs) {
                        isStale = true;
                        log.warn("[HCADAnalysisService][D3] Stale LLM analysis detected: userId={}, age={}ms, maxAge={}ms",
                            userId, ageMs, analysisMaxAgeMs);
                    }
                } else {
                    
                    log.debug("[HCADAnalysisService][D3] No analyzedAt field, treating as legacy data: userId={}", userId);
                }
                result.put("isStale", isStale);

                
                if (analysis.containsKey("riskScore")) {
                    result.put("riskScore", parseDouble(analysis.get("riskScore")));
                }
                if (analysis.containsKey("isAnomaly")) {
                    result.put("isAnomaly", parseBoolean(analysis.get("isAnomaly")));
                }
                if (analysis.containsKey("trustScore")) {
                    result.put("trustScore", parseDouble(analysis.get("trustScore")));
                }
                if (analysis.containsKey("threatType")) {
                    result.put("threatType", analysis.get("threatType").toString());
                }
                if (analysis.containsKey("threatEvidence")) {
                    result.put("threatEvidence", analysis.get("threatEvidence").toString());
                }
                
                if (analysis.containsKey("action")) {
                    result.put("action", analysis.get("action").toString());
                }
                if (analysis.containsKey("confidence")) {
                    result.put("confidence", parseDouble(analysis.get("confidence")));
                }

                if (log.isDebugEnabled()) {
                    log.debug("[HCADAnalysisService][AI Native] LLM 분석 결과 조회: userId={}, action={}, riskScore={}, isAnomaly={}, confidence={}, isStale={}",
                        userId, result.get("action"), result.get("riskScore"), result.get("isAnomaly"), result.get("confidence"), isStale);
                }
            }
            
            
            

        } catch (Exception e) {
            log.error("[HCADAnalysisService][AI Native] Redis 조회 실패: userId={}", userId, e);
        }

        return result;
    }

    
    private double parseDouble(Object value) {
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        if (value instanceof String) {
            try {
                return Double.parseDouble((String) value);
            } catch (NumberFormatException e) {
                return 0.0;
            }
        }
        return 0.0;
    }

    
    private boolean parseBoolean(Object value) {
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        if (value instanceof String) {
            return Boolean.parseBoolean((String) value);
        }
        return false;
    }

    
    private long parseLong(Object value) {
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        if (value instanceof String) {
            try {
                return Long.parseLong((String) value);
            } catch (NumberFormatException e) {
                return 0L;
            }
        }
        return 0L;
    }

    
    
    

    
    public void updateBaselineIfNeeded(HCADAnalysisResult result) {
        
        
        if (result.isAnomaly() && log.isDebugEnabled()) {
            log.debug("[HCADAnalysisService][AI Native] 이상 탐지 - Cold Path에서 학습 예정: userId={}", result.getUserId());
        }
    }

    
    
    
    
}
