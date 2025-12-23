package io.contexa.contexacommon.hcad.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.time.Instant;
import java.util.Map;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.stream.IntStream;

/**
 * HCAD (Hyper-lightweight Context Anomaly Detector) 컨텍스트
 *
 * 사용자 요청의 핵심 컨텍스트 정보를 담는 도메인 모델
 * 초경량 AI 모델이 이상 탐지를 수행하는 데 필요한 최소한의 정보만 포함
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HCADContext {

    // 사용자 식별 정보
    private String userId;
    private String sessionId;
    private String username;

    // 요청 정보
    private String requestPath;
    private String httpMethod;
    private String remoteIp;
    private String userAgent;
    private String referer;
    private String eventType; // 이벤트 유형 (LOGIN, ACCESS, ADMIN 등)

    // 시간 정보
    private Instant timestamp;
    private Long requestTime; // 요청 처리 시간 (ms)

    // 위치 정보
    private String country;
    private String city;
    private Double latitude;
    private Double longitude;

    // 행동 패턴
    private Integer recentRequestCount; // 최근 5분간 요청 수
    private Long lastRequestInterval; // 이전 요청과의 시간 간격 (ms)
    private Boolean isNewSession; // 새로운 세션 여부
    private Boolean isNewDevice; // 새로운 기기 여부
    private Boolean isNewUser; // 신규 사용자 여부 (이전 HCAD 분석 기록 없음)

    // 보안 관련
    private String authenticationMethod; // 인증 방법 (password, oauth, mfa 등)
    private Integer failedLoginAttempts; // 실패한 로그인 시도 횟수
    private Double currentTrustScore; // 현재 신뢰 점수
    private Boolean hasValidMFA; // MFA 검증 여부

    // 리소스 접근 패턴
    private String resourceType; // 접근 리소스 유형 (admin, api, static 등)
    private Boolean isSensitiveResource; // 민감한 리소스 접근 여부
    private String previousPath; // 이전 접근 경로

    // 추가 메타데이터
    private Map<String, Object> additionalAttributes;

    // ========== 확장된 메타데이터 (v3.0) ==========
    // 이전 행동 시퀀스
    private String[] previousActivities; // 최근 5개 활동
    private String[] previousPaths; // 최근 5개 경로
    private Long[] activityTimestamps; // 각 활동의 타임스탬프
    private Double sequenceSimilarity; // 시퀀스 유사도

    // 세션 상세 정보
    private Long sessionStartTime; // 세션 시작 시간
    private Integer pageViewCount; // 페이지 뷰 카운트
    private Double averagePageDuration; // 평균 페이지 체류 시간
    private Integer clickCount; // 클릭 수
    private Integer scrollDepth; // 스크롤 깊이 (0-100%)

    // 행동 패턴 상세
    private Double mouseMovementVelocity; // 마우스 이동 속도
    private Double keyboardTypingSpeed; // 타이핑 속도 (wpm)
    private Integer copyPasteCount; // 복사/붙여넣기 횟수
    private Boolean hasAutomatedPattern; // 자동화 패턴 감지

    // 네트워크 상세 정보
    private Double networkLatency; // 네트워크 지연시간 (ms)
    private Long bandwidthUsage; // 대역폭 사용량 (bytes)
    private Integer httpStatusCode; // HTTP 응답 코드
    private String contentType; // 컨텐츠 타입
    private Long responseSize; // 응답 크기

    // 시스템 레벨 정보
    private Double cpuUsage; // CPU 사용률
    private Double memoryUsage; // 메모리 사용률
    private Integer activeProcessCount; // 활성 프로세스 수
    private String[] runningServices; // 실행 중인 서비스

    // 보안 컨텍스트 확장
    private String tlsVersion; // TLS 버전
    private String cipherSuite; // 암호화 스위트
    private Boolean hasValidCertificate; // 유효한 인증서 여부
    private String[] securityHeaders; // 보안 헤더
    private Integer riskScore; // 위험 점수 (0-100)

    // ========== 추가 필드 (컴파일 오류 해결용) ==========
    private String sourceIp; // 소스 IP (remoteIp의 alias)
    private String deviceId; // 디바이스 ID
    private Double activityVelocity; // 활동 속도 (actions/minute)
    private List<String> recentActivitySequence; // 최근 활동 시퀀스
    private Map<String, Integer> activityFrequency; // 활동별 빈도
    private Double anomalyScore; // 이상 점수 (0.0-1.0)
    private Double trustScore; // 신뢰 점수 (currentTrustScore의 alias)

    // ========== Phase 2 개선: 동적 신뢰도 계산용 필드 ==========
    @Builder.Default
    private Double baselineConfidence = 0.5; // Baseline 신뢰도 (0.0-1.0), 기본값: 중립 0.5
    private Double zScore; // 통계적 Z-Score
    private String deviceType; // 디바이스 타입 (MOBILE, DESKTOP, TABLET, OTHER)
    private Double threatScore; // 위협 점수 (0.0-1.0)
    private Boolean isNewLocation; // 새로운 위치 여부

    /**
     * 컨텍스트를 컴팩트한 문자열로 변환 (AI 모델 프롬프트용)
     */
    public String toCompactString() {
        return String.format(
            "User:%s|IP:%s|Path:%s|Method:%s|UA:%s|Time:%s|Trust:%.2f|NewSession:%s|NewDevice:%s|NewUser:%s|RecentReqs:%d",
            userId != null ? userId : "anonymous",
            remoteIp,
            requestPath,
            httpMethod,
            userAgent != null ? userAgent.substring(0, Math.min(50, userAgent.length())) : "unknown",
            timestamp,
            currentTrustScore != null ? currentTrustScore : 0.5,
            isNewSession,
            isNewDevice,
            isNewUser,
            recentRequestCount != null ? recentRequestCount : 0
        );
    }

    /**
     * 벡터화를 위한 384차원 숫자 배열 변환
     *
     * AI Native v3.3.0: 규칙 기반 코드 제거
     * - 임계값 플래그 (> X ? 1.0 : 0.0) 제거
     * - 하드코딩된 키워드 체크 (contains("admin")) 제거
     * - 연속 정규화 값과 시간 원-핫만 유지
     *
     * 차원 구성:
     * - 0-31: 시간 특성 (32차원)
     * - 32-95: 행동 패턴 (64차원)
     * - 96-159: 보안 특성 (64차원)
     * - 160-223: 네트워크 특성 (64차원)
     * - 224-287: 리소스 접근 패턴 (64차원)
     * - 288-351: 디바이스/UA 특성 (64차원)
     * - 352-383: 컨텍스트 메타데이터 (32차원)
     */
    public double[] toVector() {
        double[] vector = new double[384];
        int idx = 0;

        // ========== 0-31: 시간 특성 (32차원) ==========
        long epochSecond = timestamp.getEpochSecond();
        int hour = timestamp.atZone(java.time.ZoneId.systemDefault()).getHour();
        int dayOfWeek = timestamp.atZone(java.time.ZoneId.systemDefault()).getDayOfWeek().getValue();
        int dayOfMonth = timestamp.atZone(java.time.ZoneId.systemDefault()).getDayOfMonth();
        int month = timestamp.atZone(java.time.ZoneId.systemDefault()).getMonthValue();

        // 시간대 원-핫 인코딩 (24차원)
        for (int i = 0; i < 24; i++) {
            vector[idx++] = (i == hour) ? 1.0 : 0.0;
        }

        // 요일 인코딩 (7차원)
        for (int i = 1; i <= 7; i++) {
            vector[idx++] = (i == dayOfWeek) ? 1.0 : 0.0;
        }

        // 시간 간격 (1차원)
        vector[idx++] = lastRequestInterval != null ?
            Math.tanh(lastRequestInterval / 1000.0) : 0.0; // tanh로 정규화

        // ========== 32-95: 행동 패턴 (64차원) ==========
        // 요청 빈도 다양한 스케일 (10차원)
        // AI Native v3.3.0: 연속 값만 유지, 임계값 플래그 제거
        int reqCount = recentRequestCount != null ? recentRequestCount : 0;
        vector[idx++] = Math.tanh(reqCount / 10.0);    // 10개 단위
        vector[idx++] = Math.tanh(reqCount / 50.0);    // 50개 단위
        vector[idx++] = Math.tanh(reqCount / 100.0);   // 100개 단위
        vector[idx++] = Math.tanh(reqCount / 500.0);   // 500개 단위
        vector[idx++] = Math.tanh(reqCount / 1000.0);  // 1000개 단위
        // AI Native: 임계값 플래그 제거 - LLM이 원시 연속 값으로 직접 판단
        idx += 5;  // 하위 호환성 유지 (벡터 차원)

        // 세션 특성 (10차원)
        vector[idx++] = isNewSession != null && isNewSession ? 1.0 : 0.0;
        vector[idx++] = isNewDevice != null && isNewDevice ? 1.0 : 0.0;
        vector[idx++] = sessionId != null ? 1.0 : 0.0;
        // 세션 ID 해시를 여러 차원에 분산
        if (sessionId != null) {
            int hash = sessionId.hashCode();
            for (int i = 0; i < 7; i++) {
                vector[idx++] = ((hash >> (i * 4)) & 0xF) / 15.0;
            }
        } else {
            idx += 7;
        }

        // HTTP 메서드 인코딩 (8차원)
        String[] methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"};
        for (String method : methods) {
            vector[idx++] = method.equals(httpMethod) ? 1.0 : 0.0;
        }

        // 나머지 행동 패턴 공간 (36차원) - 향후 확장용
        idx += 36;

        // ========== 96-159: 보안 특성 (64차원) ==========
        // 신뢰 점수 다양한 표현 (10차원)
        // AI Native v3.3.0: 연속 값만 유지, 임계값 플래그 제거
        double trust = currentTrustScore != null ? currentTrustScore : 0.5;
        vector[idx++] = trust;
        vector[idx++] = trust * trust;  // 제곱
        vector[idx++] = Math.sqrt(trust);  // 제곱근
        vector[idx++] = Math.log1p(trust);  // 로그
        // AI Native: 임계값 플래그 제거 - LLM이 연속 값으로 직접 판단
        idx += 6;  // 하위 호환성 유지 (벡터 차원)

        // 로그인 실패 패턴 (10차원)
        // AI Native v3.3.0: 연속 값만 유지, 임계값 플래그 제거
        int failures = failedLoginAttempts != null ? failedLoginAttempts : 0;
        vector[idx++] = Math.tanh(failures / 5.0);  // 연속 정규화 값
        // AI Native: 임계값 플래그 제거 - LLM이 연속 값으로 직접 판단
        idx += 4;  // 하위 호환성 유지 (벡터 차원)
        for (int i = 0; i < 5; i++) {
            vector[idx++] = (failures == i) ? 1.0 : 0.0;  // 0-4 실패 횟수 원-핫 (범주형 유지)
        }

        // 인증 방법 (10차원)
        String[] authMethods = {"password", "oauth", "mfa", "sso", "biometric",
                               "certificate", "token", "apikey", "ldap", "saml"};
        for (String method : authMethods) {
            vector[idx++] = method.equals(authenticationMethod) ? 1.0 : 0.0;
        }

        // MFA 및 민감 리소스 (4차원)
        vector[idx++] = hasValidMFA != null && hasValidMFA ? 1.0 : 0.0;
        vector[idx++] = hasValidMFA == null ? 0.5 : 0.0;  // MFA 상태 불명
        vector[idx++] = isSensitiveResource != null && isSensitiveResource ? 1.0 : 0.0;
        vector[idx++] = isSensitiveResource == null ? 0.5 : 0.0;

        // 확장된 보안 특성 (30차원) - v3.0
        // TLS 및 암호화 정보 (10차원)
        vector[idx++] = tlsVersion != null && tlsVersion.equals("TLSv1.3") ? 1.0 : 0.0;
        vector[idx++] = tlsVersion != null && tlsVersion.equals("TLSv1.2") ? 1.0 : 0.0;
        vector[idx++] = hasValidCertificate != null && hasValidCertificate ? 1.0 : 0.0;
        vector[idx++] = cipherSuite != null && cipherSuite.contains("AES256") ? 1.0 : 0.0;
        vector[idx++] = riskScore != null ? riskScore / 100.0 : 0.5;

        // 보안 헤더 존재 여부 (5차원)
        if (securityHeaders != null) {
            vector[idx++] = Arrays.asList(securityHeaders).contains("X-Frame-Options") ? 1.0 : 0.0;
            vector[idx++] = Arrays.asList(securityHeaders).contains("X-Content-Type-Options") ? 1.0 : 0.0;
            vector[idx++] = Arrays.asList(securityHeaders).contains("Strict-Transport-Security") ? 1.0 : 0.0;
            vector[idx++] = Arrays.asList(securityHeaders).contains("Content-Security-Policy") ? 1.0 : 0.0;
            vector[idx++] = Arrays.asList(securityHeaders).contains("X-XSS-Protection") ? 1.0 : 0.0;
        } else {
            idx += 5;
        }

        // 자동화 패턴 탐지 (5차원)
        vector[idx++] = hasAutomatedPattern != null && hasAutomatedPattern ? 1.0 : 0.0;
        vector[idx++] = mouseMovementVelocity != null ? Math.tanh(mouseMovementVelocity / 1000.0) : 0.5;
        vector[idx++] = keyboardTypingSpeed != null ? Math.tanh(keyboardTypingSpeed / 100.0) : 0.5;
        vector[idx++] = copyPasteCount != null ? Math.tanh(copyPasteCount / 10.0) : 0.0;
        vector[idx++] = clickCount != null ? Math.tanh(clickCount / 50.0) : 0.5;

        // 나머지 10차원
        idx += 10;

        // ========== 160-223: 네트워크 특성 (64차원) ==========
        // IP 주소 인코딩 (16차원)
        if (remoteIp != null) {
            String[] parts = remoteIp.split("\\.");
            if (parts.length == 4) {
                for (String part : parts) {
                    try {
                        int octet = Integer.parseInt(part);
                        // 각 옥텟을 4차원으로 인코딩
                        vector[idx++] = octet / 255.0;
                        vector[idx++] = (octet & 0xF0) / 240.0;  // 상위 4비트
                        vector[idx++] = (octet & 0x0F) / 15.0;   // 하위 4비트
                        vector[idx++] = octet > 127 ? 1.0 : 0.0; // 상위 비트
                    } catch (NumberFormatException e) {
                        idx += 4;
                    }
                }
            } else {
                idx += 16;
            }
        } else {
            idx += 16;
        }

        // 지리적 위치 (10차원)
        if (city != null || country != null) {
            vector[idx++] = city != null ? city.hashCode() % 1000 / 1000.0 : 0.0;
            vector[idx++] = country != null ? country.hashCode() % 1000 / 1000.0 : 0.0;
        } else {
            idx += 2;
        }

        if (latitude != null && longitude != null) {
            vector[idx++] = (latitude + 90) / 180.0;  // 정규화된 위도
            vector[idx++] = (longitude + 180) / 360.0; // 정규화된 경도
            vector[idx++] = Math.sin(Math.toRadians(latitude));
            vector[idx++] = Math.cos(Math.toRadians(latitude));
            vector[idx++] = Math.sin(Math.toRadians(longitude));
            vector[idx++] = Math.cos(Math.toRadians(longitude));
        } else {
            idx += 6;
        }

        // Referer 존재 여부 (2차원)
        vector[idx++] = referer != null && !referer.isEmpty() ? 1.0 : 0.0;
        vector[idx++] = referer != null && referer.contains(requestPath) ? 1.0 : 0.0;

        // 나머지 네트워크 공간 (36차원)
        idx += 36;

        // ========== 224-287: 리소스 접근 패턴 (64차원) ==========
        // 경로 깊이 및 구조 (10차원)
        // AI Native v3.3.0: 하드코딩된 키워드 체크 제거, 연속 값만 유지
        if (requestPath != null) {
            String[] pathParts = requestPath.split("/");
            vector[idx++] = Math.tanh(pathParts.length / 10.0);  // 경로 깊이 (연속)
            // AI Native: 하드코딩된 키워드 체크 제거 (admin, api, secure 등)
            // LLM이 requestPath 원시 데이터를 직접 분석
            idx += 8;  // 하위 호환성 유지 (벡터 차원)
            vector[idx++] = Math.tanh(requestPath.length() / 200.0);  // 경로 길이 정규화 (연속)
        } else {
            idx += 10;
        }

        // 리소스 타입 인코딩 (10차원)
        String[] resourceTypes = {"admin", "api", "secure", "public", "general",
                                 "static", "dynamic", "protected", "system", "user"};
        for (String type : resourceTypes) {
            vector[idx++] = type.equals(resourceType) ? 1.0 : 0.0;
        }

        // 이전 경로와의 관계 (4차원)
        if (previousPath != null && requestPath != null) {
            vector[idx++] = previousPath.equals(requestPath) ? 1.0 : 0.0;
            vector[idx++] = previousPath.contains(requestPath) ? 1.0 : 0.0;
            vector[idx++] = requestPath.contains(previousPath) ? 1.0 : 0.0;
            vector[idx++] = Math.abs(previousPath.length() - requestPath.length()) / 100.0;
        } else {
            idx += 4;
        }

        // 나머지 리소스 공간 (40차원)
        idx += 40;

        // ========== 288-351: 디바이스/UA 특성 (64차원) ==========
        // User-Agent 파싱 (20차원)
        // AI Native v3.3.0: 하드코딩된 키워드 체크 제거, 연속 값만 유지
        if (userAgent != null) {
            // AI Native: 하드코딩된 키워드 체크 제거 (windows, bot, crawler 등)
            // LLM이 userAgent 원시 데이터를 직접 분석
            idx += 17;  // 하위 호환성 유지 (벡터 차원)
            vector[idx++] = Math.tanh(userAgent.length() / 500.0);  // 길이 정규화 (연속)
            vector[idx++] = Math.tanh(userAgent.length() / 100.0);  // 다른 스케일
            vector[idx++] = Math.tanh(userAgent.length() / 300.0);  // 중간 스케일
        } else {
            idx += 20;
        }

        // 나머지 디바이스 공간 (44차원)
        idx += 44;

        // ========== 352-383: 컨텍스트 메타데이터 (32차원) ==========
        // 추가 속성들
        if (additionalAttributes != null) {
            // Content-Type 관련 (5차원)
            Object contentType = additionalAttributes.get("contentType");
            if (contentType != null) {
                String ct = contentType.toString().toLowerCase();
                vector[idx++] = ct.contains("json") ? 1.0 : 0.0;
                vector[idx++] = ct.contains("xml") ? 1.0 : 0.0;
                vector[idx++] = ct.contains("form") ? 1.0 : 0.0;
                vector[idx++] = ct.contains("multipart") ? 1.0 : 0.0;
                vector[idx++] = ct.contains("text") ? 1.0 : 0.0;
            } else {
                idx += 5;
            }

            // 보안 플래그 (2차원)
            Object secure = additionalAttributes.get("secure");
            vector[idx++] = secure != null && Boolean.TRUE.equals(secure) ? 1.0 : 0.0;

            // Query String 존재 (1차원)
            Object queryString = additionalAttributes.get("queryString");
            vector[idx++] = queryString != null && !queryString.toString().isEmpty() ? 1.0 : 0.0;
        } else {
            idx += 8;
        }

        // 사용자 식별 (5차원)
        if (userId != null) {
            int userHash = userId.hashCode();
            for (int i = 0; i < 5; i++) {
                vector[idx++] = ((userHash >> (i * 6)) & 0x3F) / 63.0;
            }
        } else {
            idx += 5;
        }

        // 나머지 메타데이터 공간 (19차원)
        for (int i = idx; i < 384; i++) {
            vector[i] = 0.0;
        }

        return vector;
    }

    /**
     * 객체를 JSON 문자열로 변환
     */
    public String toJson() {
        try {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> jsonMap = new HashMap<>();

            // 주요 필드들을 맵에 추가
            jsonMap.put("userId", userId);
            jsonMap.put("sessionId", sessionId);
            jsonMap.put("username", username);
            jsonMap.put("requestPath", requestPath);
            jsonMap.put("httpMethod", httpMethod);
            jsonMap.put("remoteIp", remoteIp);
            jsonMap.put("sourceIp", getSourceIp());
            jsonMap.put("deviceId", deviceId);
            jsonMap.put("timestamp", timestamp != null ? timestamp.toString() : null);
            jsonMap.put("trustScore", getTrustScore());
            jsonMap.put("anomalyScore", anomalyScore);
            jsonMap.put("activityVelocity", getActivityVelocity());
            jsonMap.put("recentActivitySequence", getRecentActivitySequence());
            jsonMap.put("activityFrequency", getActivityFrequency());
            jsonMap.put("isNewSession", isNewSession);
            jsonMap.put("isNewDevice", isNewDevice());
            jsonMap.put("recentRequestCount", recentRequestCount);
            jsonMap.put("failedLoginAttempts", failedLoginAttempts);
            jsonMap.put("hasValidMFA", hasValidMFA);
            jsonMap.put("isSensitiveResource", isSensitiveResource);
            jsonMap.put("riskScore", riskScore);

            // 추가 속성들
            if (additionalAttributes != null) {
                jsonMap.put("additionalAttributes", additionalAttributes);
            }

            return mapper.writeValueAsString(jsonMap);
        } catch (JsonProcessingException e) {
            // 에러 발생 시 간단한 문자열 반환
            return String.format("{\"userId\":\"%s\",\"error\":\"JSON conversion failed\"}",
                               userId != null ? userId : "unknown");
        }
    }

    // ========== 호환성을 위한 추가 getter 메소드들 ==========

    /**
     * sourceIp getter (remoteIp의 alias)
     */
    public String getSourceIp() {
        return sourceIp != null ? sourceIp : remoteIp;
    }

    /**
     * trustScore getter (currentTrustScore의 alias)
     */
    public Double getTrustScore() {
        return trustScore != null ? trustScore : currentTrustScore;
    }

    /**
     * activityVelocity getter (요청 빈도 기반 계산)
     */
    public Double getActivityVelocity() {
        if (activityVelocity != null) {
            return activityVelocity;
        }
        // recentRequestCount를 기반으로 계산 (5분간 요청 수 -> 분당 요청 수)
        if (recentRequestCount != null && recentRequestCount > 0) {
            return recentRequestCount / 5.0; // 5분간 요청 수를 분당으로 변환
        }
        return 0.0;
    }

    /**
     * recentActivitySequence getter
     */
    public List<String> getRecentActivitySequence() {
        if (recentActivitySequence != null) {
            return recentActivitySequence;
        }
        // previousActivities를 List로 변환
        if (previousActivities != null) {
            return Arrays.asList(previousActivities);
        }
        return new ArrayList<>();
    }

    /**
     * activityFrequency getter
     */
    public Map<String, Integer> getActivityFrequency() {
        if (activityFrequency != null) {
            return activityFrequency;
        }
        // 빈 맵 반환
        return new HashMap<>();
    }

    /**
     * anomalyScore getter
     */
    public Double getAnomalyScore() {
        if (anomalyScore != null) {
            return anomalyScore;
        }
        // trustScore의 역수로 계산
        if (currentTrustScore != null) {
            return 1.0 - currentTrustScore;
        }
        return 0.5;
    }

    /**
     * deviceId getter
     */
    public String getDeviceId() {
        if (deviceId != null) {
            return deviceId;
        }
        // userAgent의 해시를 deviceId로 사용
        if (userAgent != null) {
            return String.valueOf(userAgent.hashCode());
        }
        return null;
    }

    /**
     * isNewDevice getter (Boolean 타입 호환)
     */
    public boolean isNewDevice() {
        return isNewDevice != null && isNewDevice;
    }

    /**
     * eventType getter - httpMethod를 기반으로 이벤트 유형 반환
     */
    public String getEventType() {
        if (httpMethod != null) {
            return httpMethod;
        }
        return "UNKNOWN";
    }

    /**
     * setEventType - httpMethod 설정
     */
    public void setEventType(String eventType) {
        this.httpMethod = eventType;
    }

    /**
     * setTimestamp - Instant 타입으로 설정
     */
    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * setAdditionalData - additionalAttributes 설정
     */
    public void setAdditionalData(Map<String, Object> data) {
        if (this.additionalAttributes == null) {
            this.additionalAttributes = new HashMap<>();
        }
        if (data != null) {
            this.additionalAttributes.putAll(data);
        }
    }

    /**
     * 추가 setter 메소드들
     */
    public void setNewSession(boolean newSession) {
        this.isNewSession = newSession;
    }

    public void setNewDevice(boolean newDevice) {
        this.isNewDevice = newDevice;
    }

    public void setNewUser(boolean newUser) {
        this.isNewUser = newUser;
    }

    public void setSensitiveResource(boolean sensitiveResource) {
        this.isSensitiveResource = sensitiveResource;
    }

    public void setRecentRequestCount(int count) {
        this.recentRequestCount = count;
    }

    public void setLastRequestInterval(long interval) {
        this.lastRequestInterval = interval;
    }

    public void setCurrentTrustScore(double score) {
        this.currentTrustScore = score;
    }

    public void setFailedLoginAttempts(int attempts) {
        this.failedLoginAttempts = attempts;
    }

    public void setHasValidMFA(boolean hasValidMFA) {
        this.hasValidMFA = hasValidMFA;
    }

    public void setAuthenticationMethod(String method) {
        this.authenticationMethod = method;
    }

    public void setResourceType(String type) {
        this.resourceType = type;
    }

    public void setPreviousPath(String path) {
        this.previousPath = path;
    }

}