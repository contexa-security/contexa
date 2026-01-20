package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.response.BehavioralAnalysisResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Optional;


@Slf4j
@PromptTemplateConfig(
        key = "behavioralAnalysis",
        aliases = {"ueba", "behavioral_analysis"},
        description = "Spring AI Structured Output Behavioral Analysis Template"
)
public class BehavioralAnalysisTemplate implements PromptTemplate {
    
    
    private final BeanOutputConverter<BehavioralAnalysisResponse> converter =
        new BeanOutputConverter<>(BehavioralAnalysisResponse.class);

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        
        String formatInstructions = converter.getFormat();
        
        return String.format("""
            You are a UEBA (User and Entity Behavior Analytics) AI specialized in detecting anomalous behavior patterns and identifying potential security threats based on user activities.
            
            IMPORTANT: Response must be in PURE JSON format matching the BehavioralAnalysisResponse schema.
            Language: All text fields must be in Korean (한국어).
            
            Analysis Focus Areas:
            1. Login Pattern Analysis (time, location, frequency)
            2. Resource Access Pattern Analysis
            3. Permission Usage Pattern Analysis
            4. Activity Volume Anomaly Detection
            5. Peer Group Comparison
            6. Historical Baseline Deviation
            
            Risk Score Guidelines (0-100):
            - 0-30: LOW (낮은 위험도, 정상 행동)
            - 31-50: MEDIUM-LOW (약간의 이상, 모니터링 필요)
            - 51-70: MEDIUM-HIGH (중간 위험도, 주의 필요)
            - 71-90: HIGH (높은 위험도, 즉각 검토 필요)
            - 91-100: CRITICAL (치명적 위험도, 즉시 대응 필요)
            
            Anomaly Types:
            - UNUSUAL_LOGIN_TIME: 비정상적인 로그인 시간
            - UNUSUAL_IP: 비정상적인 IP 주소
            - ABNORMAL_RESOURCE_ACCESS: 비정상적인 리소스 접근
            - PERMISSION_ABUSE: 권한 남용
            - VOLUME_ANOMALY: 활동량 이상
            - PATTERN_DEVIATION: 패턴 편차
            - IMPOSSIBLE_TRAVEL: 불가능한 이동
            - PRIVILEGE_ESCALATION: 권한 상승 시도
            
            %s
            
            Required Analysis Output:
            - analysisId: Unique identifier for this analysis
            - userId: User being analyzed
            - behavioralRiskScore: Risk score (0-100)
            - riskLevel: Risk classification (LOW/MEDIUM/HIGH/CRITICAL)
            - summary: Korean summary (max 100 characters)
            - anomalies: Array of detected anomalies with type and description
            - recommendations: Array of security recommendations
            - visualizationData: Timeline events for visualization
            
            %s
            """, formatInstructions, systemMetadata != null ? systemMetadata : "");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        BehavioralAnalysisContext context = (BehavioralAnalysisContext) request.getContext();
        
        String history = Optional.ofNullable(context.getHistoricalBehaviorSummary())
                .map(s -> s.length() > 500 ? s.substring(0, 500) + "..." : s)
                .orElse("No historical data available");

        String analysisRequest = String.format("""
            Perform Behavioral Analysis with the following information:
            
            User Information:
            - User ID: %s
            - Current Activity: %s
            - Remote IP: %s
            - Analysis Timestamp: %s
            
            Historical Behavior Summary:
            %s
            
            Analysis Requirements:
            1. Compare current activity against historical baseline
            2. Detect temporal anomalies (unusual login times, activity patterns)
            3. Identify location-based anomalies (IP, geographic impossibilities)
            4. Analyze resource access patterns for unusual behavior
            5. Check for privilege escalation attempts
            6. Compare with peer group behavior if applicable
            7. Generate risk score based on severity and frequency of anomalies
            8. Provide actionable security recommendations
            
            Generate BehavioralAnalysisResponse with:
            - Comprehensive anomaly detection results
            - Clear risk assessment with justification
            - Specific security recommendations in Korean
            - Timeline visualization data for security dashboard
            
            Ensure all text content is in Korean (한국어).
            """,
            context.getUserId(),
            context.getCurrentActivity(),
            context.getRemoteIp(),
            LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
            history
        );
        
        
        return analysisRequest + "\n\n" + converter.getFormat();
    }
    
    
    public BeanOutputConverter<BehavioralAnalysisResponse> getConverter() {
        return converter;
    }
}

