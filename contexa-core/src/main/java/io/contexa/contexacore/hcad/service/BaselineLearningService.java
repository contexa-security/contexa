package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.BaselineMatchStatus;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.hcad.util.UserAgentParser;
import io.contexa.contexacore.properties.HcadProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class BaselineLearningService {

    private final @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate;
    private final HcadProperties hcadProperties;

    private static final String BASELINE_KEY_PREFIX = "security:hcad:baseline:";
    private static final Duration BASELINE_TTL = Duration.ofDays(30);

    public boolean learnIfNormal(String userId, SecurityDecision decision, SecurityEvent event) {
        if (!hcadProperties.getBaseline().getLearning().isEnabled()) {
            return false;
        }

        if (userId == null || decision == null) return false;
        if (!shouldLearnFromSecurityEvent(decision)) return false;

        try {
            BaselineVector currentBaseline = getBaseline(userId);
            BaselineVector newBaseline = updateWithEMAFromSecurityEvent(currentBaseline, userId, decision, event);
            saveBaseline(userId, newBaseline);
            return true;

        } catch (Exception e) {
            log.error("[BaselineLearningService] SecurityEvent 기반 학습 실패: userId={}", userId, e);
            return false;
        }
    }

    private boolean shouldLearnFromSecurityEvent(SecurityDecision decision) {
        return decision.getAction() == ZeroTrustAction.ALLOW;
    }

    private BaselineVector updateWithEMAFromSecurityEvent(BaselineVector current, String userId,
                                                          SecurityDecision decision, SecurityEvent event) {

        double rawTrustScore = 1.0 - decision.getRiskScore();
        double currentTrustScore = Math.max(0.0, Math.min(1.0, rawTrustScore));

        String currentIp = event != null ? event.getSourceIp() : null;
        Integer currentHour = extractHourFromSecurityEvent(event);
        String currentPath = extractPath(event);
        String currentUserAgent = event != null ? event.getUserAgent() : null;

        if (currentUserAgent == null || currentUserAgent.isEmpty()) {
            log.error("[Baseline][AI Native v8.5] UA missing - learning blocked: userId={}", userId);
            return current;
        }
        String uaSignatureForValidation = extractUASignature(currentUserAgent);
        if ("Browser (Desktop)".equals(uaSignatureForValidation)) {
            log.error("[Baseline][AI Native v8.5] UA parsing failed - learning blocked: userId={}, ua={}",
                    userId, currentUserAgent.length() > 50 ? currentUserAgent.substring(0, 50) + "..." : currentUserAgent);
            return current;
        }

        if (current == null) {

            BaselineVector.BaselineVectorBuilder builder = BaselineVector.builder()
                    .userId(userId)
                    .avgTrustScore(currentTrustScore)
                    .avgRequestCount(1L)
                    .updateCount(1L)
                    .lastUpdated(Instant.now());

            if (currentIp != null) {
                String ipRange = extractIpRange(currentIp);
                builder.normalIpRanges(new String[]{ipRange});
            }
            if (currentHour != null) {
                builder.normalAccessHours(new Integer[]{currentHour});
            }
            if (currentPath != null) {
                builder.frequentPaths(new String[]{currentPath});
            }

            String uaSignature = extractUASignature(currentUserAgent);
            if (uaSignature != null && !uaSignature.equals("unknown") &&
                    !uaSignature.equals("unknown (unknown)")) {
                builder.normalUserAgents(new String[]{uaSignature});
            } else {

                String truncatedUA = currentUserAgent.length() > 100
                        ? currentUserAgent.substring(0, 100) : currentUserAgent;
                builder.normalUserAgents(new String[]{truncatedUA});
                log.error("[Baseline] SecurityEvent first learning - UA parsing failed, storing raw: {}", truncatedUA);
            }

            String os = extractOS(currentUserAgent);
            if (!os.equals("Unknown")) {
                builder.normalOperatingSystems(new String[]{os});
            }

            return builder.build();
        }

        double oldTrustScore = current.getAvgTrustScore() != null ? current.getAvgTrustScore() : 0.5;
        double alpha = hcadProperties.getBaseline().getLearning().getAlpha();
        double newTrustScore = alpha * currentTrustScore + (1 - alpha) * oldTrustScore;

        long oldUpdateCount = current.getUpdateCount() != null ? current.getUpdateCount() : 0L;
        long oldRequestCount = current.getAvgRequestCount() != null ? current.getAvgRequestCount() : 0L;

        String[] normalIpRanges = updateNormalIpRanges(current.getNormalIpRanges(), currentIp);
        Integer[] normalAccessHours = updateNormalAccessHours(current.getNormalAccessHours(), currentHour);
        String[] frequentPaths = updateFrequentPaths(current.getFrequentPaths(), currentPath);

        String normalizedUA = extractUASignature(currentUserAgent);
        String uaForUpdate = (normalizedUA != null && !normalizedUA.equals("unknown") &&
                !normalizedUA.equals("unknown (unknown)"))
                ? normalizedUA : currentUserAgent;
        String[] normalUserAgents = updateNormalUserAgents(current.getNormalUserAgents(), uaForUpdate);

        String currentOS = extractOS(currentUserAgent);
        String[] normalOperatingSystems = updateNormalOperatingSystems(
                current.getNormalOperatingSystems(), currentOS);

        return BaselineVector.builder()
                .userId(userId)
                .avgTrustScore(newTrustScore)
                .avgRequestCount(oldRequestCount + 1)
                .updateCount(oldUpdateCount + 1)
                .lastUpdated(Instant.now())

                .normalIpRanges(normalIpRanges)
                .normalAccessHours(normalAccessHours)
                .frequentPaths(frequentPaths)
                .normalUserAgents(normalUserAgents)
                .normalOperatingSystems(normalOperatingSystems)
                .build();
    }

    private Integer extractHourFromSecurityEvent(SecurityEvent event) {
        if (event == null || event.getTimestamp() == null) {
            return null;
        }
        return event.getTimestamp().getHour();
    }

    private String extractIpRange(String ip) {
        if (ip == null || ip.isEmpty()) {
            return null;
        }

        if (isLoopback(ip)) {
            return "loopback";
        }

        if (ip.contains(":")) {
            return normalizeIPv6Range(ip);
        }

        int lastDot = ip.lastIndexOf('.');
        if (lastDot > 0) {
            return ip.substring(0, lastDot);
        }
        return ip;
    }

    private boolean isLoopback(String ip) {
        if (ip == null) {
            return false;
        }

        if ("127.0.0.1".equals(ip) || ip.startsWith("127.")) {
            return true;
        }

        if ("::1".equals(ip) ||
                "0:0:0:0:0:0:0:1".equals(ip) ||
                "0000:0000:0000:0000:0000:0000:0000:0001".equals(ip)) {
            return true;
        }
        return false;
    }

    private String normalizeIPv6Range(String ipv6) {
        if (ipv6 == null || ipv6.isEmpty()) {
            return null;
        }

        String expanded = expandIPv6(ipv6);
        String[] segments = expanded.split(":");

        if (segments.length >= 4) {
            return String.format("%s:%s:%s:%s",
                    normalizeIPv6Segment(segments[0]),
                    normalizeIPv6Segment(segments[1]),
                    normalizeIPv6Segment(segments[2]),
                    normalizeIPv6Segment(segments[3]));
        }
        return ipv6;
    }

    private String expandIPv6(String ipv6) {
        if (!ipv6.contains("::")) {
            return ipv6;
        }
        String[] parts = ipv6.split("::", 2);
        String[] leftSegments = parts[0].isEmpty() ? new String[0] : parts[0].split(":");
        String[] rightSegments = parts.length > 1 && !parts[1].isEmpty() ? parts[1].split(":") : new String[0];

        int missingSegments = 8 - leftSegments.length - rightSegments.length;
        StringBuilder expanded = new StringBuilder();

        for (String seg : leftSegments) {
            if (!expanded.isEmpty()) expanded.append(":");
            expanded.append(seg);
        }
        for (int i = 0; i < missingSegments; i++) {
            if (!expanded.isEmpty()) expanded.append(":");
            expanded.append("0");
        }
        for (String seg : rightSegments) {
            if (!expanded.isEmpty()) expanded.append(":");
            expanded.append(seg);
        }
        return expanded.toString();
    }

    private String normalizeIPv6Segment(String segment) {
        if (segment == null || segment.isEmpty()) {
            return "0";
        }

        String normalized = segment.replaceFirst("^0+", "");
        return normalized.isEmpty() ? "0" : normalized;
    }

    private String[] updateNormalIpRanges(String[] current, String newIp) {
        if (newIp == null) {
            return current;
        }
        String ipRange = extractIpRange(newIp);
        if (ipRange == null) {
            return current;
        }

        if (current == null || current.length == 0) {
            return new String[]{ipRange};
        }

        for (String existing : current) {
            if (ipRange.equals(existing)) {
                return current;
            }
        }

        if (current.length >= 5) {

            String[] updated = new String[5];
            System.arraycopy(current, 1, updated, 0, 4);
            updated[4] = ipRange;
            return updated;
        }

        String[] updated = new String[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = ipRange;
        return updated;
    }

    private Integer[] updateNormalAccessHours(Integer[] current, Integer newHour) {
        if (newHour == null || newHour < 0 || newHour > 23) {
            return current;
        }

        if (current == null || current.length == 0) {
            return new Integer[]{newHour};
        }

        for (Integer existing : current) {
            if (newHour.equals(existing)) {
                return current;
            }
        }

        if (current.length >= 24) {
            return current;
        }

        Integer[] updated = new Integer[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = newHour;
        return updated;
    }

    private String[] updateFrequentPaths(String[] current, String newPath) {
        if (newPath == null || newPath.isEmpty()) {
            return current;
        }

        if (current == null || current.length == 0) {
            return new String[]{newPath};
        }

        for (String existing : current) {
            if (newPath.equals(existing)) {
                return current;
            }
        }

        if (current.length >= 10) {

            String[] updated = new String[10];
            System.arraycopy(current, 1, updated, 0, 9);
            updated[9] = newPath;
            return updated;
        }

        String[] updated = new String[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = newPath;
        return updated;
    }

    private String[] updateNormalUserAgents(String[] current, String newUserAgent) {
        if (newUserAgent == null || newUserAgent.isEmpty()) {
            return current;
        }

        if (newUserAgent.length() > 100) {
            newUserAgent = newUserAgent.substring(0, 100);
        }

        if (current == null || current.length == 0) {
            return new String[]{newUserAgent};
        }

        for (String existing : current) {
            if (newUserAgent.equals(existing)) {
                return current;
            }
        }

        if (current.length >= 5) {

            String[] updated = new String[5];
            System.arraycopy(current, 1, updated, 0, 4);
            updated[4] = newUserAgent;
            return updated;
        }

        String[] updated = new String[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = newUserAgent;
        return updated;
    }

    private String[] updateNormalOperatingSystems(String[] current, String newOS) {
        if (newOS == null || newOS.isEmpty() || newOS.equals("Unknown")) {
            return current;
        }

        if (current == null || current.length == 0) {
            return new String[]{newOS};
        }

        for (String existing : current) {
            if (newOS.equals(existing)) {
                return current;
            }
        }

        if (current.length >= 5) {

            String[] updated = new String[5];
            System.arraycopy(current, 1, updated, 0, 4);
            updated[4] = newOS;
            return updated;
        }

        String[] updated = new String[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = newOS;
        return updated;
    }

    public BaselineVector getBaseline(String userId) {
        if (redisTemplate == null || userId == null) {
            return null;
        }

        BaselineVector userBaseline = getUserBaseline(userId);
        if (userBaseline != null) {
            return userBaseline;
        }

        String organizationId = extractOrganizationId(userId);
        if (organizationId != null) {
            BaselineVector orgBaseline = getOrganizationBaseline(organizationId);
            if (orgBaseline != null) {

                return BaselineVector.builder()
                        .userId(userId)
                        .avgTrustScore(orgBaseline.getAvgTrustScore())
                        .avgRequestCount(orgBaseline.getAvgRequestCount())
                        .updateCount(0L)
                        .lastUpdated(orgBaseline.getLastUpdated())
                        .normalIpRanges(orgBaseline.getNormalIpRanges())
                        .normalAccessHours(orgBaseline.getNormalAccessHours())
                        .frequentPaths(orgBaseline.getFrequentPaths())
                        .normalUserAgents(null)
                        .build();
            }
        }

        return null;
    }

    private BaselineVector getUserBaseline(String userId) {
        try {
            String key = BASELINE_KEY_PREFIX + userId;
            Map<Object, Object> data = redisTemplate.opsForHash().entries(key);

            if (data.isEmpty()) {
                return null;
            }

            return BaselineVector.builder()
                    .userId(userId)
                    .avgTrustScore(parseDouble(data.get("avgTrustScore")))
                    .avgRequestCount(parseLong(data.get("avgRequestCount")))
                    .updateCount(parseLong(data.get("updateCount")))
                    .lastUpdated(parseInstant(data.get("lastUpdated")))

                    .normalIpRanges(parseStringArray(data.get("normalIpRanges")))
                    .normalAccessHours(parseIntegerArray(data.get("normalAccessHours")))
                    .frequentPaths(parseStringArray(data.get("frequentPaths")))

                    .normalUserAgents(parseStringArray(data.get("normalUserAgents")))

                    .normalOperatingSystems(parseStringArray(data.get("normalOperatingSystems")))
                    .build();

        } catch (Exception e) {
            log.error("[BaselineLearningService] 사용자 Baseline 조회 실패: userId={}", userId, e);
            return null;
        }
    }

    public BaselineVector getOrganizationBaseline(String organizationId) {
        if (redisTemplate == null || organizationId == null) {
            return null;
        }

        try {
            String key = BASELINE_KEY_PREFIX + "org:" + organizationId;
            Map<Object, Object> data = redisTemplate.opsForHash().entries(key);

            if (data == null || data.isEmpty()) {
                return null;
            }

            return BaselineVector.builder()
                    .userId("org:" + organizationId)
                    .avgTrustScore(parseDouble(data.get("avgTrustScore")))
                    .avgRequestCount(parseLong(data.get("avgRequestCount")))
                    .updateCount(parseLong(data.get("updateCount")))
                    .lastUpdated(parseInstant(data.get("lastUpdated")))
                    .normalIpRanges(parseStringArray(data.get("normalIpRanges")))
                    .normalAccessHours(parseIntegerArray(data.get("normalAccessHours")))
                    .frequentPaths(parseStringArray(data.get("frequentPaths")))
                    .build();

        } catch (Exception e) {
            log.error("[BaselineLearningService] 조직 Baseline 조회 실패: organizationId={}", organizationId, e);
            return null;
        }
    }

    private String extractOrganizationId(String userId) {
        if (userId == null || userId.isEmpty()) {
            return null;
        }

        int underscoreIndex = userId.indexOf('_');
        if (underscoreIndex > 0) {
            return userId.substring(0, underscoreIndex);
        }

        int atIndex = userId.indexOf('@');
        if (atIndex > 0) {
            return userId.substring(0, atIndex);
        }

        return "default";
    }

    private String[] parseStringArray(Object value) {
        if (value instanceof String && !((String) value).isEmpty()) {
            return ((String) value).split(",");
        }
        return null;
    }

    private Integer[] parseIntegerArray(Object value) {
        if (value instanceof String && !((String) value).isEmpty()) {
            try {
                return Arrays.stream(((String) value).split(","))
                        .map(Integer::parseInt)
                        .toArray(Integer[]::new);
            } catch (NumberFormatException e) {
                log.error("[BaselineLearningService] Integer array parsing failed: {}", value);
                return null;
            }
        }
        return null;
    }

    private void saveBaseline(String userId, BaselineVector baseline) {
        if (redisTemplate == null || userId == null || baseline == null) {
            return;
        }

        try {
            String key = BASELINE_KEY_PREFIX + userId;
            Map<String, Object> data = new HashMap<>();
            data.put("userId", userId);
            data.put("avgTrustScore", baseline.getAvgTrustScore());
            data.put("avgRequestCount", baseline.getAvgRequestCount());
            data.put("updateCount", baseline.getUpdateCount());

            data.put("lastUpdated", baseline.getLastUpdated() != null ?
                    baseline.getLastUpdated().toString() : Instant.now().toString());

            if (baseline.getNormalIpRanges() != null && baseline.getNormalIpRanges().length > 0) {
                data.put("normalIpRanges", String.join(",", baseline.getNormalIpRanges()));
            }
            if (baseline.getNormalAccessHours() != null && baseline.getNormalAccessHours().length > 0) {
                data.put("normalAccessHours", Arrays.stream(baseline.getNormalAccessHours())
                        .map(String::valueOf)
                        .collect(java.util.stream.Collectors.joining(",")));
            }
            if (baseline.getFrequentPaths() != null && baseline.getFrequentPaths().length > 0) {
                data.put("frequentPaths", String.join(",", baseline.getFrequentPaths()));
            }

            if (baseline.getNormalUserAgents() != null && baseline.getNormalUserAgents().length > 0) {
                data.put("normalUserAgents", String.join(",", baseline.getNormalUserAgents()));
            }

            if (baseline.getNormalOperatingSystems() != null && baseline.getNormalOperatingSystems().length > 0) {
                data.put("normalOperatingSystems", String.join(",", baseline.getNormalOperatingSystems()));
            }

            redisTemplate.opsForHash().putAll(key, data);
            redisTemplate.expire(key, BASELINE_TTL);

        } catch (Exception e) {
            log.error("[BaselineLearningService] Baseline 저장 실패: userId={}", userId, e);
        }
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

    private Instant parseInstant(Object value) {
        if (value instanceof String) {
            try {
                return Instant.parse((String) value);
            } catch (Exception e) {
                return Instant.now();
            }
        }
        return Instant.now();
    }

    public String buildBaselinePromptContext(String userId, SecurityEvent currentEvent) {
        if (userId == null) {
            return "Baseline: User ID not available";
        }

        BaselineVector baseline = getBaseline(userId);
        if (baseline == null) {

            return buildNewUserWarning(userId, currentEvent);
        }

        String[] normalIps = baseline.getNormalIpRanges();
        Integer[] normalHours = baseline.getNormalAccessHours();
        String[] normalUserAgents = baseline.getNormalUserAgents();
        String baselineUASignature = normalUserAgents != null && normalUserAgents.length > 0
                ? extractUASignature(normalUserAgents[0]) : "none";

        StringBuilder sb = new StringBuilder();

        if (normalIps != null && normalIps.length > 0) {
            sb.append("Known IPs: ").append(String.join(", ", normalIps)).append("\n");
        }

        if (normalHours != null && normalHours.length > 0) {
            StringBuilder hours = new StringBuilder();
            for (int i = 0; i < normalHours.length; i++) {
                if (i > 0) hours.append(", ");
                hours.append(normalHours[i]);
            }
            sb.append("Known Hours: ").append(hours).append("\n");
        }

        sb.append("Known UA: ").append(baselineUASignature).append("\n");

        return sb.toString();
    }

    private String buildNewUserWarning(String userId, SecurityEvent currentEvent) {
        StringBuilder sb = new StringBuilder();

        sb.append("=== CRITICAL: NO USER BASELINE ===\n");
        sb.append("This user has NO established behavior pattern.\n");
        sb.append("Zero Trust Principle: \"Never Trust, Always Verify\"\n\n");

        sb.append("WITHOUT baseline comparison:\n");
        sb.append("- You CANNOT determine if this behavior is normal\n");
        sb.append("- You CANNOT compare against historical patterns\n");
        sb.append("- This could be a first-time attacker\n\n");

        sb.append("Current Request Context:\n");
        if (currentEvent != null) {
            String sourceIp = currentEvent.getSourceIp();
            String normalizedIp = extractIpRange(sourceIp);
            sb.append(String.format("  IP: %s\n", normalizedIp != null ? normalizedIp : "NOT_PROVIDED"));

            if (currentEvent.getTimestamp() != null) {
                sb.append(String.format("  Hour: %d\n", currentEvent.getTimestamp().getHour()));
            }

            String userAgent = currentEvent.getUserAgent();
            String uaSignature = extractUASignature(userAgent);
            sb.append(String.format("  UA: %s\n", uaSignature));
        }
        sb.append("\n");

        sb.append("=== BASELINE CONSIDERATIONS ===\n");
        sb.append("No traditional baseline profile established for this user.\n\n");

        sb.append("Decision guidance (facts, not rules):\n");
        sb.append("- RELATED CONTEXT contains VERIFIED NORMAL BEHAVIOR (past ALLOW decisions)\n");
        sb.append("- If RELATED CONTEXT has documents matching current OS/IP/Hour → verified pattern exists\n");
        sb.append("- If RELATED CONTEXT is EMPTY → no verified patterns to compare against\n");
        sb.append("- Cannot verify behavior without comparison data\n\n");

        return sb.toString();
    }

    private String extractPath(SecurityEvent event) {
        if (event == null) {
            return null;
        }

        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && metadata.containsKey("targetResource")) {
            Object targetResource = metadata.get("targetResource");
            if (targetResource != null && !targetResource.toString().isEmpty()) {
                return targetResource.toString();
            }
        }

        if (metadata != null && metadata.containsKey("requestPath")) {
            Object path = metadata.get("requestPath");
            if (path != null) {
                return path.toString();
            }
        }

        return null;
    }

    private String extractOS(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Unknown";
        }

        if (userAgent.contains("Android")) {
            return "Android";
        }

        if (userAgent.contains("iPhone") || userAgent.contains("iPad") || userAgent.contains("iPod")) {
            return "iOS";
        }

        if (userAgent.contains("Windows")) {
            return "Windows";
        }

        if (userAgent.contains("Mac OS") || userAgent.contains("Macintosh")) {
            return "Mac";
        }

        if (userAgent.contains("CrOS")) {
            return "ChromeOS";
        }

        if (userAgent.contains("Linux") && !userAgent.contains("Android")) {
            return "Linux";
        }

        return "Unknown";
    }

    private String extractUASignature(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Browser";
        }

        if (userAgent.contains("Chrome/") && !userAgent.contains("Edg/")) {
            return extractBrowserVersion(userAgent, "Chrome/");
        } else if (userAgent.contains("Edg/")) {
            String browser = extractBrowserVersion(userAgent, "Edg/");
            return browser.replace("Edg", "Edge");
        } else if (userAgent.contains("Firefox/")) {
            return extractBrowserVersion(userAgent, "Firefox/");
        } else if (userAgent.contains("Safari/") && !userAgent.contains("Chrome") && !userAgent.contains("Edg")) {
            String browser = extractBrowserVersion(userAgent, "Version/");
            return browser.replace("Version", "Safari");
        }

        return "Browser";
    }

    private String extractBrowserVersion(String userAgent, String prefix) {
        int idx = userAgent.indexOf(prefix);
        if (idx == -1) return "unknown";

        int start = idx + prefix.length();
        if (start >= userAgent.length()) return "unknown";

        int end = start;
        while (end < userAgent.length()) {
            char c = userAgent.charAt(end);
            if (c == '.' || c == ' ' || !Character.isDigit(c)) {
                break;
            }
            end++;
        }

        if (end == start) return "unknown";

        String version = userAgent.substring(start, end);
        String browserName = prefix.replace("/", "");
        return browserName + "/" + version;
    }
}
