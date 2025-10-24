package io.contexa.contexacommon.domain.context;

import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.SecurityLevel;
import lombok.Getter;
import lombok.Setter;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 사용자 행동 분석 진단을 위한 확장된 데이터 컨텍스트.
 * AI 진단 파이프라인 전체에서 데이터 운반체 역할을 합니다.
 * 시퀀스 패턴, 세션 정보, 디바이스 핑거프린트 등을 포함합니다.
 */
@Getter
@Setter
public class BehavioralAnalysisContext extends IAMContext {

    private static final String IAM_CONTEXT_TYPE = "BEHAVIOR_ANALYSIS";

    // 기본 필드
    private String userId;
    private String currentActivity; // 예: "API /api/v1/admin/users 접근 시도"
    private String remoteIp;
    private String historicalBehaviorSummary;

    // 시퀀스 정보 - 행동 패턴 순서 추적
    private List<String> recentActivitySequence = new ArrayList<>();  // 최근 활동 시퀀스
    private List<Duration> activityIntervals = new ArrayList<>();     // 활동 간 시간 간격
    private String previousActivity;                                  // 직전 활동
    private LocalDateTime lastActivityTime;                          // 마지막 활동 시간
    private Duration timeSinceLastActivity;                          // 마지막 활동 이후 경과 시간

    // 세션 및 디바이스 정보
    private String sessionFingerprint;                               // 세션 핑거프린트
    private String deviceFingerprint;                               // 디바이스 핑거프린트
    private String userAgent;                                        // 사용자 에이전트
    private String browserInfo;                                      // 브라우저 정보
    private String osInfo;                                          // 운영체제 정보
    private boolean isNewDevice;                                    // 새로운 디바이스 여부
    private boolean isNewLocation;                                  // 새로운 위치 여부

    // 빈도 및 통계 정보
    private int dailyActivityCount;                                 // 일일 활동 횟수
    private int hourlyActivityCount;                               // 시간당 활동 횟수
    private double activityVelocity;                               // 활동 속도 (actions/minute)
    private Map<String, Integer> activityFrequency = new HashMap<>(); // 활동별 빈도

    // 위험 지표
    private double behaviorAnomalyScore;                           // 행동 이상 점수 (0.0-1.0)
    private List<String> anomalyIndicators = new ArrayList<>();    // 이상 지표 목록
    private boolean hasRiskyPattern;                               // 위험 패턴 포함 여부
    private String riskCategory;                                   // 위험 카테고리

    // 컨텍스트 정보
    private String accessContext;                                  // 접근 컨텍스트 (업무/개인/긴급 등)
    private String geoLocation;                                    // 지리적 위치
    private String networkSegment;                                 // 네트워크 세그먼트
    private boolean isVpnConnection;                               // VPN 연결 여부

    public BehavioralAnalysisContext() {
        this(SecurityLevel.STANDARD, AuditRequirement.DETAILED);
    }

    public BehavioralAnalysisContext(SecurityLevel securityLevel, AuditRequirement auditRequirement) {
        super(securityLevel, auditRequirement);
    }


    @Override
    public String getIAMContextType() {
        return IAM_CONTEXT_TYPE;
    }

    // 헬퍼 메서드들

    /**
     * 새로운 활동을 시퀀스에 추가
     */
    public void addActivityToSequence(String activity) {
        if (currentActivity != null && !currentActivity.equals(activity)) {
            previousActivity = currentActivity;
        }

        recentActivitySequence.add(activity);

        // 최대 20개의 최근 활동만 유지
        if (recentActivitySequence.size() > 20) {
            recentActivitySequence.remove(0);
        }

        // 시간 간격 계산
        if (lastActivityTime != null) {
            Duration interval = Duration.between(lastActivityTime, LocalDateTime.now());
            activityIntervals.add(interval);
            timeSinceLastActivity = interval;

            // 활동 속도 계산 (분당 활동 수)
            if (interval.toSeconds() > 0) {
                activityVelocity = 60.0 / interval.toSeconds();
            }
        }

        currentActivity = activity;
        lastActivityTime = LocalDateTime.now();

        // 활동 빈도 업데이트
        activityFrequency.put(activity, activityFrequency.getOrDefault(activity, 0) + 1);
    }

    /**
     * 이상 지표 추가
     */
    public void addAnomalyIndicator(String indicator) {
        if (!anomalyIndicators.contains(indicator)) {
            anomalyIndicators.add(indicator);
            hasRiskyPattern = true;
        }
    }

    /**
     * 세션 핑거프린트 생성
     */
    public void generateSessionFingerprint() {
        StringBuilder sb = new StringBuilder();
        sb.append(userId != null ? userId : "unknown").append(":");
        sb.append(remoteIp != null ? remoteIp : "0.0.0.0").append(":");
        sb.append(userAgent != null ? userAgent.hashCode() : "0").append(":");
        sb.append(System.currentTimeMillis());

        this.sessionFingerprint = String.valueOf(sb.toString().hashCode());
    }

    /**
     * 디바이스 핑거프린트 생성
     */
    public void generateDeviceFingerprint() {
        StringBuilder sb = new StringBuilder();
        sb.append(userAgent != null ? userAgent : "unknown").append(":");
        sb.append(browserInfo != null ? browserInfo : "unknown").append(":");
        sb.append(osInfo != null ? osInfo : "unknown").append(":");
        sb.append(remoteIp != null ? remoteIp.substring(0, remoteIp.lastIndexOf('.')) : "0.0.0");

        this.deviceFingerprint = String.valueOf(sb.toString().hashCode());
    }

    /**
     * 행동 패턴이 정상 범위인지 확인
     */
    public boolean isNormalBehaviorPattern() {
        return behaviorAnomalyScore < 0.5 && !hasRiskyPattern;
    }

    /**
     * 시퀀스 패턴 문자열 생성 (벡터 임베딩용)
     */
    public String getSequencePattern() {
        if (recentActivitySequence.isEmpty()) {
            return "NO_SEQUENCE";
        }
        return String.join(" -> ", recentActivitySequence);
    }

    /**
     * 컨텍스트 요약 정보 생성
     */
    public Map<String, Object> getContextSummary() {
        Map<String, Object> summary = new HashMap<>();
        summary.put("userId", userId);
        summary.put("currentActivity", currentActivity);
        summary.put("sequenceLength", recentActivitySequence.size());
        summary.put("anomalyScore", behaviorAnomalyScore);
        summary.put("hasRiskyPattern", hasRiskyPattern);
        summary.put("activityVelocity", activityVelocity);
        summary.put("isNewDevice", isNewDevice);
        summary.put("isNewLocation", isNewLocation);
        return summary;
    }
}
