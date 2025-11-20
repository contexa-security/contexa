package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.hcad.constants.HCADRedisKeys;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.service.HCADBaselineCacheService;
import io.contexa.contexacore.hcad.service.HCADContextExtractor;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * HCAD BaselineVector 조회 API
 *
 * 실제 요청 기반 테스트를 위한 Baseline 실시간 조회 엔드포인트
 *
 * @author contexa
 * @since 3.0.0
 */
@RestController
@RequestMapping("/api/hcad")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
@Slf4j
public class HCADBaselineController {

    private final HCADBaselineCacheService baselineCacheService;
    private final RedisTemplate<String, Object> redisTemplate;
    private final HCADContextExtractor hcadContextExtractor;

    /**
     * 현재 요청의 실제 사용자 ID 반환
     *
     * 익명 사용자는 "anonymous:{IP}" 형식으로 반환
     * 인증 사용자는 실제 username 반환
     *
     * @param request HTTP 요청
     * @param authentication 인증 정보
     * @return 사용자 ID 정보
     */
    @GetMapping("/current-user")
    public ResponseEntity<Map<String, String>> getCurrentUser(
            HttpServletRequest request,
            Authentication authentication) {
        try {
            // HCADContextExtractor를 사용하여 서버와 동일한 로직으로 userId 생성
            HCADContext context = hcadContextExtractor.extractContext(request, authentication);
            String userId = context.getUserId();

            Map<String, String> response = new HashMap<>();
            response.put("userId", userId);
            response.put("isAnonymous", userId.startsWith("anonymous:") ? "true" : "false");

            log.debug("[HCADBaselineController] Current user: userId={}, isAnonymous={}",
                     userId, userId.startsWith("anonymous:"));

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("[HCADBaselineController] Failed to get current user", e);

            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            errorResponse.put("userId", "unknown");

            return ResponseEntity.status(500).body(errorResponse);
        }
    }

    /**
     * 사용자별 BaselineVector 조회
     *
     * @param userId 사용자 ID
     * @return BaselineVector 정보
     */
    @GetMapping("/baseline/{userId}")
    public ResponseEntity<Map<String, Object>> getBaseline(@PathVariable String userId) {
        try {
            String key = HCADRedisKeys.baselineVector(userId);
            Object value = redisTemplate.opsForValue().get(key);

            if (value instanceof BaselineVector) {
                BaselineVector baseline = (BaselineVector) value;

                Map<String, Object> response = new HashMap<>();
                response.put("userId", baseline.getUserId());
                response.put("updateCount", baseline.getUpdateCount());
                response.put("confidence", baseline.getConfidence());
                response.put("lastUpdated", baseline.getLastUpdated());
                response.put("vectorNorm", calculateVectorNorm(baseline.getVector()));
                response.put("avgRequestCount", baseline.getAvgRequestCount());
                response.put("meanRequestInterval", baseline.getMeanRequestInterval());
                response.put("avgTrustScore", baseline.getAvgTrustScore());

                log.debug("[HCADBaselineController] Baseline 조회 성공: userId={}, updateCount={}, confidence={}",
                    userId, baseline.getUpdateCount(), baseline.getConfidence());

                return ResponseEntity.ok(response);
            } else {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "Baseline not found");
                errorResponse.put("userId", userId);
                errorResponse.put("message", "새 사용자 또는 학습되지 않은 사용자입니다.");

                log.info("[HCADBaselineController] Baseline 없음: userId={}", userId);

                return ResponseEntity.status(404).body(errorResponse);
            }
        } catch (Exception e) {
            log.error("[HCADBaselineController] Baseline 조회 실패: userId={}", userId, e);

            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            errorResponse.put("userId", userId);

            return ResponseEntity.status(500).body(errorResponse);
        }
    }

    /**
     * 모든 사용자 BaselineVector 목록 조회
     *
     * @return BaselineVector 목록
     */
    @GetMapping("/baseline/all")
    public ResponseEntity<List<Map<String, Object>>> getAllBaselines() {
        try {
            Set<String> keys = redisTemplate.keys("security:baseline:vector:*");
            List<Map<String, Object>> baselines = new ArrayList<>();

            if (keys != null) {
                for (String key : keys) {
                    Object value = redisTemplate.opsForValue().get(key);
                    if (value instanceof BaselineVector) {
                        BaselineVector baseline = (BaselineVector) value;

                        Map<String, Object> item = new HashMap<>();
                        item.put("userId", baseline.getUserId());
                        item.put("updateCount", baseline.getUpdateCount());
                        item.put("confidence", baseline.getConfidence());
                        item.put("lastUpdated", baseline.getLastUpdated());
                        item.put("vectorNorm", calculateVectorNorm(baseline.getVector()));

                        baselines.add(item);
                    }
                }
            }

            log.info("[HCADBaselineController] 전체 Baseline 조회: {}개", baselines.size());

            return ResponseEntity.ok(baselines);
        } catch (Exception e) {
            log.error("[HCADBaselineController] 전체 Baseline 조회 실패", e);
            return ResponseEntity.status(500).body(List.of());
        }
    }

    /**
     * Redis BaselineVector 키 목록 조회
     *
     * @return Redis 키 목록
     */
    @GetMapping("/baseline/keys")
    public ResponseEntity<Map<String, Object>> getBaselineKeys() {
        try {
            Set<String> keys = redisTemplate.keys("security:baseline:vector:*");

            Map<String, Object> response = new HashMap<>();
            response.put("totalCount", keys != null ? keys.size() : 0);
            response.put("keys", keys);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("[HCADBaselineController] 키 목록 조회 실패", e);

            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());

            return ResponseEntity.status(500).body(errorResponse);
        }
    }

    /**
     * 벡터 노름(길이) 계산
     */
    private double calculateVectorNorm(double[] vector) {
        if (vector == null) return 0.0;

        double sum = 0.0;
        for (double v : vector) {
            sum += v * v;
        }
        return Math.sqrt(sum);
    }
}
