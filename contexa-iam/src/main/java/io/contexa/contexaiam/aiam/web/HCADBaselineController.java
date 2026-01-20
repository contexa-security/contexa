package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.hcad.domain.HCADContext;
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


@RequestMapping("/api/hcad")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
@Slf4j
public class HCADBaselineController {

    
    private final RedisTemplate<String, Object> redisTemplate;
    private final HCADContextExtractor hcadContextExtractor;

    
    private static final String BASELINE_VECTOR_KEY_PREFIX = "security:baseline:vector:";

    
    @GetMapping("/current-user")
    public ResponseEntity<Map<String, String>> getCurrentUser(
            HttpServletRequest request,
            Authentication authentication) {
        try {
            
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

    
    @GetMapping("/baseline/{userId}")
    public ResponseEntity<Map<String, Object>> getBaseline(@PathVariable String userId) {
        try {
            
            String key = BASELINE_VECTOR_KEY_PREFIX + userId;
            Object value = redisTemplate.opsForValue().get(key);

            if (value instanceof BaselineVector) {
                BaselineVector baseline = (BaselineVector) value;

                Map<String, Object> response = new HashMap<>();
                response.put("userId", baseline.getUserId());
                response.put("updateCount", baseline.getUpdateCount());
                response.put("lastUpdated", baseline.getLastUpdated());
                response.put("avgRequestCount", baseline.getAvgRequestCount());
                response.put("avgTrustScore", baseline.getAvgTrustScore());
                
                response.put("normalIpRanges", baseline.getNormalIpRanges());
                response.put("normalAccessHours", baseline.getNormalAccessHours());
                response.put("frequentPaths", baseline.getFrequentPaths());
                response.put("normalUserAgents", baseline.getNormalUserAgents());

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
                        item.put("lastUpdated", baseline.getLastUpdated());
                        item.put("avgTrustScore", baseline.getAvgTrustScore());

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

    
    
    
}
