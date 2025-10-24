package io.contexa.contexacore.autonomous.domain;

import lombok.Data;
import java.util.HashMap;
import java.util.Map;

/**
 * 세션 위협 지표
 * 
 * 세션 컨텍스트 분석 결과를 담는 도메인 객체입니다.
 * IP 변경, User-Agent 변경, 의심스러운 활동 등의 지표를 포함합니다.
 */
@Data
public class SessionThreatIndicators {
    
    private boolean ipChanged = false;
    private boolean userAgentChanged = false;
    private boolean suspiciousActivity = false;
    private double additionalRisk = 0.0;
    private Map<String, String> indicators = new HashMap<>();
    
    /**
     * 세션 하이재킹이 의심되는지 여부
     */
    public boolean isSessionHijackSuspected() {
        return ipChanged || userAgentChanged || suspiciousActivity || additionalRisk > 0.5;
    }
    
    /**
     * 세션을 무효화해야 하는지 여부
     */
    public boolean shouldInvalidateSession() {
        // IP와 UA가 모두 변경되거나, 위험도가 0.7 이상이면 무효화
        return (ipChanged && userAgentChanged) || additionalRisk > 0.7;
    }
    
    /**
     * 위험도 추가
     */
    public void addRisk(double risk) {
        this.additionalRisk = Math.min(1.0, this.additionalRisk + risk);
    }
    
    /**
     * 지표 추가
     */
    public void addIndicator(String key, String value) {
        this.indicators.put(key, value);
    }
    
    /**
     * 위협 지표 추가 (점수와 설명 포함)
     */
    public void addIndicator(String key, double score, String description) {
        this.indicators.put(key, description);
        this.additionalRisk = Math.min(1.0, this.additionalRisk + score);
    }
    
    /**
     * 위협 점수 증가
     */
    public void incrementScore(double score) {
        this.additionalRisk = Math.min(1.0, this.additionalRisk + score);
    }
    
    @Override
    public String toString() {
        return String.format("SessionThreatIndicators{ipChanged=%s, uaChanged=%s, suspicious=%s, risk=%.2f, indicators=%s}",
                ipChanged, userAgentChanged, suspiciousActivity, additionalRisk, indicators);
    }
}