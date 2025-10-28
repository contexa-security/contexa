package io.contexa.contexacore.dashboard.metrics.plane;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.dashboard.api.DomainMetrics;
import io.contexa.contexacore.dashboard.api.EventRecorder;
import io.contexa.contexacore.hcad.service.HCADSimilarityCalculator.TrustedSimilarityResult;
import io.contexa.contexacore.plane.service.SensitiveResourceService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 직교 신호 수집기 (Orthogonal Signal Collector)
 *
 * HCAD 4-Layer와 독립적인 신호를 수집하여 불일치 탐지에 사용합니다.
 *
 * 7차원 신호 구성:
 * - Layer 1-4: HCAD 기존 신호 (TrustedSimilarityResult에서 추출)
 * - Network Signal: ASN, GeoIP, Proxy 탐지 (새로운 독립 신호)
 * - Crypto Signal: TLS Fingerprint, WebAuthn, Device Binding (새로운 독립 신호)
 * - Timing Signal: Shannon Entropy, Jitter, Interval Distribution (새로운 독립 신호)
 *
 * 외부기관 1 피드백 반영:
 * - 직교(독립) 신호 부족 문제 해결
 * - HCAD Layer와 독립적인 3개 신호 추가
 *
 * @author contexa
 * @since 3.0
 */
@Slf4j
@Service
public class OrthogonalSignalCollector implements DomainMetrics, EventRecorder {

    @Autowired(required = false)
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired(required = false)
    private RestTemplate restTemplate;

    @Autowired(required = false)
    private SensitiveResourceService sensitiveResourceService;

    // ===== 설정값 =====

    /**
     * GeoIP 조회 방식: "maxmind" 또는 "api"
     */
    @Value("${hcad.signal.geoip.provider:api}")
    private String geoipProvider;

    /**
     * GeoIP API URL (api 방식 사용 시)
     */
    @Value("${hcad.signal.geoip.api.url:https://ipapi.co/{ip}/json/}")
    private String geoipApiUrl;

    /**
     * 타이밍 신호 버킷 수 (Shannon Entropy 계산용)
     */
    @Value("${hcad.signal.timing.bucket.count:7}")
    private int timingBucketCount;

    /**
     * Redis에 저장할 최근 인터벌 개수
     */
    @Value("${hcad.signal.timing.interval.history.size:100}")
    private int intervalHistorySize;

    // ===== Public Methods =====

    /**
     * 7차원 직교 신호 수집
     *
     * @param event SecurityEvent
     * @param hcadResult HCAD 분석 결과 (Layer 1-4 점수 포함)
     * @return OrthogonalSignals (7차원 벡터)
     */
    public OrthogonalSignals collect(SecurityEvent event, TrustedSimilarityResult hcadResult) {
        try {
            // ===== HCAD Layer 점수 직접 참조 (TrustedSimilarityResult에서 가져옴) =====
            // 근사치 계산 제거, 실제 계산된 Layer 점수 사용
            double layer1 = hcadResult.getLayer1ThreatSearchScore();
            double layer2 = hcadResult.getLayer2BaselineSimilarity();
            double layer3 = hcadResult.getLayer3AnomalyScore();
            double layer4 = hcadResult.getLayer4CorrelationScore();

            return OrthogonalSignals.builder()
                    // HCAD Layers (HCADSimilarityCalculator에서 계산된 실제 값 사용)
                    .layer1Signal(layer1)  // RAG 기반 위협 사례 검색 점수
                    .layer2Signal(layer2)  // 기준선 유사도 점수
                    .layer3Signal(layer3)  // 이상도 분석 점수 (1.0 - anomaly)
                    .layer4Signal(layer4)  // 위협 상관관계 분석 점수

                    // Orthogonal Signals (새로운 독립 신호)
                    .networkSignal(collectNetworkSignal(event))
                    .cryptoSignal(collectCryptoSignal(event))
                    .timingSignal(collectTimingSignal(event))

                    .timestamp(LocalDateTime.now())
                    .build();

        } catch (Exception e) {
            log.error("[OrthogonalSignal] Failed to collect signals for event {}: {}",
                    event.getEventId(), e.getMessage());

            // 예외 발생 시 기본값 반환
            return OrthogonalSignals.builder()
                    .layer1Signal(0.5)
                    .layer2Signal(0.5)
                    .layer3Signal(0.5)
                    .layer4Signal(0.5)
                    .networkSignal(0.5)
                    .cryptoSignal(0.5)
                    .timingSignal(0.5)
                    .timestamp(LocalDateTime.now())
                    .build();
        }
    }

    // ===== Private Methods: Network Signal =====

    /**
     * Network 신호: ASN + GeoIP + Proxy 탐지
     *
     * 점수 구성:
     * - ASN 변화: +0.3
     * - GeoIP 불일치 (불가능한 이동): +0.2
     * - Proxy/VPN/Tor 탐지: +0.3
     *
     * @return 0.0 ~ 1.0 (높을수록 의심스러움)
     */
    private double collectNetworkSignal(SecurityEvent event) {
        double score = 0.5; // 기본값 (중립)

        try {
            String userId = event.getUserId();
            String currentIp = event.getSourceIp();

            if (currentIp == null) {
                return score;
            }

            // 1. ASN 변화 감지
            String currentAsn = getAsn(currentIp);
            String previousAsn = getUserPreviousAsn(userId);

            if (previousAsn != null && !previousAsn.equals(currentAsn)) {
                score += 0.3;
                log.debug("[NetworkSignal] ASN changed for user {}: {} -> {}",
                        userId, previousAsn, currentAsn);
            }

            // 현재 ASN 저장
            saveUserCurrentAsn(userId, currentAsn);

            // 2. GeoIP 불일치 (불가능한 이동)
            if (isGeoIpAnomaly(event, currentIp)) {
                score += 0.2;
                log.debug("[NetworkSignal] GeoIP anomaly detected for user {}", userId);
            }

            // 3. Proxy/VPN/Tor 탐지
            if (isProxyDetected(currentIp)) {
                score += 0.3;
                log.debug("[NetworkSignal] Proxy/VPN detected for IP {}", currentIp);
            }

        } catch (Exception e) {
            log.warn("[NetworkSignal] Failed to collect network signal: {}", e.getMessage());
        }

        return Math.min(1.0, score);
    }

    /**
     * ASN 조회 (GeoIP 데이터 활용)
     */
    private String getAsn(String ipAddress) {
        if (redisTemplate == null) {
            return "UNKNOWN";
        }

        // Redis 캐시 조회 (5분 TTL)
        String cacheKey = "geoip:asn:" + ipAddress;
        Object cached = redisTemplate.opsForValue().get(cacheKey);
        if (cached != null) {
            return cached.toString();
        }

        // GeoIP 조회
        String asn = queryGeoIpAsn(ipAddress);

        // 캐시 저장
        redisTemplate.opsForValue().set(cacheKey, asn, Duration.ofMinutes(5));

        return asn;
    }

    /**
     * GeoIP ASN 조회 (외부 API 또는 MaxMind DB)
     *
     * 비용 절감: 외부 API 호출 주석처리 (월 $100-500 비용 발생)
     * TODO: MaxMind GeoLite2-ASN.mmdb 로컬 DB 통합 시 활성화
     */
    private String queryGeoIpAsn(String ipAddress) {
        if ("maxmind".equals(geoipProvider)) {
            // TODO: MaxMind GeoIP2 라이브러리 통합
            // DatabaseReader reader = new DatabaseReader.Builder(new File("GeoLite2-ASN.mmdb")).build();
            // AsnResponse response = reader.asn(InetAddress.getByName(ipAddress));
            // return "AS" + response.getAutonomousSystemNumber();
            log.debug("[GeoIP] MaxMind provider not implemented yet");
        }

        // 비용 절감: API 방식 주석처리
        // API 방식 (ipapi.co) - 비활성화
        /*
        try {
            if (restTemplate != null) {
                String url = geoipApiUrl.replace("{ip}", ipAddress);
                Map<String, Object> response = restTemplate.getForObject(url, Map.class);

                if (response != null && response.containsKey("asn")) {
                    return response.get("asn").toString();
                }
            }
        } catch (Exception e) {
            log.warn("[GeoIP] Failed to query ASN for IP {}: {}", ipAddress, e.getMessage());
        }
        */

        // GeoIP API 비활성화 상태: UNKNOWN 반환
        log.debug("[GeoIP] API disabled for cost saving, returning UNKNOWN for IP: {}", ipAddress);
        return "UNKNOWN";
    }

    /**
     * 사용자의 이전 ASN 조회
     */
    private String getUserPreviousAsn(String userId) {
        if (redisTemplate == null) {
            return null;
        }

        String key = "user:asn:" + userId;
        Object asn = redisTemplate.opsForValue().get(key);
        return asn != null ? asn.toString() : null;
    }

    /**
     * 사용자의 현재 ASN 저장 (24시간 TTL)
     */
    private void saveUserCurrentAsn(String userId, String asn) {
        if (redisTemplate != null && asn != null) {
            String key = "user:asn:" + userId;
            redisTemplate.opsForValue().set(key, asn, Duration.ofDays(1));
        }
    }

    /**
     * GeoIP 이상 탐지 (불가능한 이동)
     *
     * 예: 미국 뉴욕 → 러시아 모스크바 (1분 내 이동 불가능)
     */
    private boolean isGeoIpAnomaly(SecurityEvent event, String currentIp) {
        // TODO: 구현
        // 1. 이전 위치 조회 (country, city)
        // 2. 현재 위치 조회
        // 3. 거리 계산 (Haversine formula)
        // 4. 시간 차이 계산
        // 5. 속도 계산 (distance / time)
        // 6. 임계값 초과 시 true (예: 1000 km/h 이상)

        return false; // 미구현
    }

    /**
     * Proxy/VPN/Tor 탐지
     *
     * 방법:
     * 1. IP-API.com의 proxy 필드 확인
     * 2. 또는 별도 Proxy Detection API 사용 (ProxyCheck.io, IPQualityScore)
     */
    private boolean isProxyDetected(String ipAddress) {
        try {
            if (restTemplate != null) {
                String url = geoipApiUrl.replace("{ip}", ipAddress);
                Map<String, Object> response = restTemplate.getForObject(url, Map.class);

                if (response != null) {
                    // ipapi.co는 "proxy" 필드 제공하지 않음
                    // 대안: "org" 필드에 "VPN", "Proxy" 포함 여부 체크
                    Object org = response.get("org");
                    if (org != null) {
                        String orgStr = org.toString().toLowerCase();
                        return orgStr.contains("vpn") ||
                               orgStr.contains("proxy") ||
                               orgStr.contains("tor") ||
                               orgStr.contains("hosting");
                    }
                }
            }
        } catch (Exception e) {
            log.debug("[ProxyDetection] Failed to detect proxy for IP {}: {}", ipAddress, e.getMessage());
        }

        return false;
    }

    // ===== Private Methods: Crypto Signal =====

    /**
     * Crypto 신호: TLS Fingerprint + WebAuthn + Device Binding
     *
     * 점수 구성:
     * - TLS Fingerprint 불일치: +0.4
     * - WebAuthn 부재 (@Protectable 리소스인 경우): +0.3
     * - Device Binding 불일치: +0.3
     *
     * @return 0.0 ~ 1.0 (높을수록 의심스러움)
     */
    private double collectCryptoSignal(SecurityEvent event) {
        double score = 0.5; // 기본값

        try {
            String userId = event.getUserId();

            // 1. TLS Fingerprint 불일치
            String currentTls = extractTlsFingerprint(event);
            String expectedTls = getUserExpectedTlsFingerprint(userId);

            if (expectedTls != null && currentTls != null && !expectedTls.equals(currentTls)) {
                score += 0.4;
                log.debug("[CryptoSignal] TLS fingerprint mismatch for user {}", userId);
            }

            // 현재 TLS Fingerprint 저장
            if (currentTls != null) {
                saveUserCurrentTlsFingerprint(userId, currentTls);
            }

            // 2. WebAuthn 부재 (민감 리소스인데 WebAuthn 없음)
            if (sensitiveResourceService != null &&
                sensitiveResourceService.isProtectableResource(event.getTargetResource(), event.getProtocol())) {

                if (!isWebAuthnVerified(event)) {
                    score += 0.3;
                    log.debug("[CryptoSignal] WebAuthn not verified for @Protectable resource: {}",
                            event.getTargetResource());
                }
            }

            // 3. Device Binding 불일치
            // TODO: Device Fingerprint 구현 (Canvas Fingerprint, AudioContext Fingerprint 등)

        } catch (Exception e) {
            log.warn("[CryptoSignal] Failed to collect crypto signal: {}", e.getMessage());
        }

        return Math.min(1.0, score);
    }

    /**
     * TLS Fingerprint 추출 (JA3 해시)
     */
    private String extractTlsFingerprint(SecurityEvent event) {
        if (event.getMetadata() != null) {
            Object tls = event.getMetadata().get("tlsFingerprint");
            return tls != null ? tls.toString() : null;
        }
        return null;
    }

    /**
     * 사용자의 예상 TLS Fingerprint 조회
     */
    private String getUserExpectedTlsFingerprint(String userId) {
        if (redisTemplate == null) {
            return null;
        }

        String key = "user:tls:" + userId;
        Object tls = redisTemplate.opsForValue().get(key);
        return tls != null ? tls.toString() : null;
    }

    /**
     * 사용자의 현재 TLS Fingerprint 저장 (7일 TTL)
     */
    private void saveUserCurrentTlsFingerprint(String userId, String tlsFingerprint) {
        if (redisTemplate != null && tlsFingerprint != null) {
            String key = "user:tls:" + userId;
            redisTemplate.opsForValue().set(key, tlsFingerprint, Duration.ofDays(7));
        }
    }

    /**
     * WebAuthn 검증 여부 확인
     */
    private boolean isWebAuthnVerified(SecurityEvent event) {
        if (event.getMetadata() != null) {
            Object webauthn = event.getMetadata().get("webauthnVerified");
            return Boolean.TRUE.equals(webauthn);
        }
        return false;
    }

    // ===== Private Methods: Timing Signal =====

    /**
     * Timing 신호: Shannon Entropy + Jitter + Interval Distribution
     *
     * PII 최소화: 타이밍을 버킷화 (100ms, 500ms, 1s, 5s, 30s, 1m, >1m)
     *
     * 점수 구성:
     * - Shannon Entropy가 너무 낮거나 높음 (봇 의심): +0.3
     * - Jitter가 매우 높음 (불안정한 네트워크 또는 봇): +0.2
     *
     * @return 0.0 ~ 1.0 (높을수록 의심스러움)
     */
    private double collectTimingSignal(SecurityEvent event) {
        double score = 0.5; // 기본값

        try {
            String userId = event.getUserId();

            // 1. 최근 인터벌 조회
            List<Long> recentIntervals = getUserRecentIntervals(userId);

            if (recentIntervals.size() < 5) {
                // 데이터 부족 시 중립 점수
                return score;
            }

            // 2. Shannon Entropy 계산 (randomness 측정)
            double entropy = calculateShannonEntropy(recentIntervals);

            // 3. Jitter 계산 (간격 변동성)
            double jitter = calculateJitter(recentIntervals);

            // 4. 이상 탐지
            // 너무 일정하거나 (봇) 너무 랜덤하면 (스크립트) 의심
            if (entropy < 0.3 || entropy > 0.9) {
                score += 0.3;
                log.debug("[TimingSignal] Abnormal entropy for user {}: {}", userId, entropy);
            }

            if (jitter > 0.5) {
                score += 0.2;
                log.debug("[TimingSignal] High jitter for user {}: {}", userId, jitter);
            }

            // 5. 현재 인터벌 저장
            saveUserInterval(userId, event.getTimestamp());

        } catch (Exception e) {
            log.warn("[TimingSignal] Failed to collect timing signal: {}", e.getMessage());
        }

        return Math.min(1.0, score);
    }

    /**
     * 사용자의 최근 요청 인터벌 조회 (밀리초 단위)
     */
    private List<Long> getUserRecentIntervals(String userId) {
        if (redisTemplate == null) {
            return List.of();
        }

        String key = "user:intervals:" + userId;
        List<Object> intervals = redisTemplate.opsForList().range(key, 0, -1);

        if (intervals == null) {
            return List.of();
        }

        return intervals.stream()
                .filter(o -> o instanceof Number)
                .map(o -> ((Number) o).longValue())
                .collect(Collectors.toList());
    }

    /**
     * 현재 요청 인터벌 저장
     */
    private void saveUserInterval(String userId, LocalDateTime currentTimestamp) {
        if (redisTemplate == null) {
            return;
        }

        String key = "user:intervals:" + userId;
        String lastKey = "user:last.timestamp:" + userId;

        // 이전 타임스탬프 조회
        Object lastObj = redisTemplate.opsForValue().get(lastKey);
        if (lastObj != null) {
            LocalDateTime lastTimestamp = (LocalDateTime) lastObj;
            long interval = Duration.between(lastTimestamp, currentTimestamp).toMillis();

            // 인터벌 저장 (최대 100개)
            redisTemplate.opsForList().leftPush(key, interval);
            redisTemplate.opsForList().trim(key, 0, intervalHistorySize - 1);
        }

        // 현재 타임스탬프 저장
        redisTemplate.opsForValue().set(lastKey, currentTimestamp, Duration.ofHours(1));
    }

    /**
     * Shannon Entropy 계산 (타이밍 패턴 랜덤성)
     *
     * H(X) = -Σ p(x) * log2(p(x))
     *
     * 정규화: 0.0 (완전 일정) ~ 1.0 (완전 랜덤)
     */
    private double calculateShannonEntropy(List<Long> intervals) {
        if (intervals.isEmpty()) {
            return 0.5;
        }

        // 1. Interval을 버킷화 (PII 최소화)
        Map<TimingBucket, Integer> bucketCounts = bucketizeIntervals(intervals);

        // 2. Shannon Entropy 계산
        int total = intervals.size();
        double entropy = 0.0;

        for (int count : bucketCounts.values()) {
            if (count > 0) {
                double p = (double) count / total;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }

        // 3. 정규화 (0~1)
        double maxEntropy = Math.log(timingBucketCount) / Math.log(2);
        return maxEntropy > 0 ? entropy / maxEntropy : 0.5;
    }

    /**
     * 타이밍 버킷화 (PII 최소화)
     */
    private Map<TimingBucket, Integer> bucketizeIntervals(List<Long> intervals) {
        Map<TimingBucket, Integer> bucketCounts = new EnumMap<>(TimingBucket.class);

        for (Long interval : intervals) {
            TimingBucket bucket = getTimingBucket(interval);
            bucketCounts.merge(bucket, 1, Integer::sum);
        }

        return bucketCounts;
    }

    /**
     * 인터벌을 버킷으로 분류
     */
    private TimingBucket getTimingBucket(long intervalMs) {
        if (intervalMs < 100) return TimingBucket.BUCKET_100MS;
        if (intervalMs < 500) return TimingBucket.BUCKET_500MS;
        if (intervalMs < 1000) return TimingBucket.BUCKET_1S;
        if (intervalMs < 5000) return TimingBucket.BUCKET_5S;
        if (intervalMs < 30000) return TimingBucket.BUCKET_30S;
        if (intervalMs < 60000) return TimingBucket.BUCKET_1M;
        return TimingBucket.BUCKET_OVER_1M;
    }

    /**
     * Jitter 계산 (간격 변동성)
     *
     * Jitter = StdDev / Mean
     *
     * 정규화: 0.0 (일정) ~ 1.0 (매우 불안정)
     */
    private double calculateJitter(List<Long> intervals) {
        if (intervals.size() < 2) {
            return 0.0;
        }

        double mean = intervals.stream()
                .mapToLong(Long::longValue)
                .average()
                .orElse(0.0);

        if (mean == 0.0) {
            return 0.0;
        }

        double variance = intervals.stream()
                .mapToDouble(interval -> Math.pow(interval - mean, 2))
                .average()
                .orElse(0.0);

        double stdDev = Math.sqrt(variance);
        double jitter = stdDev / mean;

        // 정규화 (0~1), 최대 1.0으로 제한
        return Math.min(1.0, jitter);
    }

    // ===== Inner Classes =====

    /**
     * 타이밍 버킷 enum
     */
    private enum TimingBucket {
        BUCKET_100MS,   // < 100ms
        BUCKET_500MS,   // 100ms ~ 500ms
        BUCKET_1S,      // 500ms ~ 1s
        BUCKET_5S,      // 1s ~ 5s
        BUCKET_30S,     // 5s ~ 30s
        BUCKET_1M,      // 30s ~ 1m
        BUCKET_OVER_1M  // > 1m
    }

    /**
     * 직교 신호 클래스 (7차원 벡터)
     */
    @lombok.Builder
    @lombok.Getter
    public static class OrthogonalSignals {
        // HCAD Layers (기존)
        private final double layer1Signal;
        private final double layer2Signal;
        private final double layer3Signal;
        private final double layer4Signal;

        // Orthogonal Signals (새로운 독립 신호)
        private final double networkSignal;
        private final double cryptoSignal;
        private final double timingSignal;

        private final LocalDateTime timestamp;

        /**
         * 7차원 배열로 변환
         */
        public double[] toArray() {
            return new double[] {
                layer1Signal,
                layer2Signal,
                layer3Signal,
                layer4Signal,
                networkSignal,
                cryptoSignal,
                timingSignal
            };
        }

        /**
         * 평균 신호 값
         */
        public double getMean() {
            return (layer1Signal + layer2Signal + layer3Signal + layer4Signal +
                    networkSignal + cryptoSignal + timingSignal) / 7.0;
        }
    }

    // ===== MetricsCollector 인터페이스 구현 =====

    @Override
    public String getDomain() {
        return "plane";
    }

    @Override
    public void initialize() {
        log.info("OrthogonalSignalCollector 초기화 완료");
    }

    @Override
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("domain", "plane");
        stats.put("initialized", true);
        return stats;
    }

    @Override
    public void reset() {
        log.info("OrthogonalSignalCollector 리셋 완료");
    }

    // ===== DomainMetrics 인터페이스 구현 =====

    @Override
    public double getHealthScore() {
        return 1.0; // 직교 신호 수집기는 항상 정상 작동
    }

    @Override
    public Map<String, Double> getKeyMetrics() {
        Map<String, Double> metrics = new HashMap<>();
        metrics.put("health", 1.0);
        return metrics;
    }

    // ===== EventRecorder 인터페이스 구현 =====

    @Override
    public void recordEvent(String eventType, Map<String, Object> metadata) {
        log.debug("Event recorded: {}", eventType);
    }

    @Override
    public void recordDuration(String operationName, long durationNanos) {
        log.debug("Duration recorded: {} ns", durationNanos);
    }
}
