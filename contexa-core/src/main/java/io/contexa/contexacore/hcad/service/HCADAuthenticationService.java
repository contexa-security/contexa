package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.HCADContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * HCAD Authentication 정보 관리 서비스
 *
 * Spring Security Authentication 객체에 HCAD 이상 탐지 정보 저장:
 * - Authentication.details에 이상 탐지 정보 추가
 * - 심각도 레벨 계산
 * - 모달 알림용 상세 정보 생성
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class HCADAuthenticationService {

    /**
     * 이상탐지 정보를 Authentication.details에 저장
     * 개선: 통합 임계값 전달
     *
     * @param authentication Spring Security Authentication 객체
     * @param context HCAD 컨텍스트
     * @param similarityScore 유사도 점수
     * @param anomalyScore 이상 점수
     * @param currentThreshold 현재 임계값
     */
    public void setAnomalyInfoInAuthentication(Authentication authentication, HCADContext context,
                                               double similarityScore, double anomalyScore, double currentThreshold) {
        try {
            if (authentication instanceof AbstractAuthenticationToken token) {

                // 기존 details 가져오기 또는 새로 생성
                Map<String, Object> details = new HashMap<>();
                if (token.getDetails() instanceof Map) {
                    details.putAll((Map<String, Object>) token.getDetails());
                }

                // 이상탐지 정보 추가
                details.put("anomalyDetected", true);
                details.put("similarityScore", similarityScore);
                details.put("anomalyScore", anomalyScore);
                details.put("threshold", currentThreshold);
                details.put("detectionTime", Instant.now().toString());
                details.put("requestPath", context.getRequestPath());
                details.put("remoteIp", context.getRemoteIp());
                details.put("userAgent", context.getUserAgent());

                // 모달 알림을 위한 상세 정보
                Map<String, Object> anomalyInfo = new HashMap<>();
                anomalyInfo.put("type", "behavioral_anomaly");
                anomalyInfo.put("severity", getSeverityLevel(anomalyScore));
                anomalyInfo.put("description", "비정상적인 사용자 행동이 감지되었습니다.");
                anomalyInfo.put("recommendation", "보안을 위해 추가 모니터링이 진행됩니다.");

                details.put("anomalyInfo", anomalyInfo);

                // Authentication에 업데이트된 details 설정
                token.setDetails(details);

                if (log.isDebugEnabled()) {
                    log.debug("[HCAD] Anomaly info set in Authentication.details - userId: {}, similarity: {}",
                        context.getUserId(), String.format("%.3f", similarityScore));
                }
            }
        } catch (Exception e) {
            log.error("[HCAD] Failed to set anomaly info in Authentication.details", e);
        }
    }

    /**
     * 이상 점수에 따른 심각도 결정
     *
     * @param anomalyScore 이상 점수
     * @return 심각도 레벨 (high, medium, low)
     */
    public String getSeverityLevel(double anomalyScore) {
        if (anomalyScore >= 0.8) {
            return "high";
        } else if (anomalyScore >= 0.6) {
            return "medium";
        } else {
            return "low";
        }
    }
}
