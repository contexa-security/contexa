package io.contexa.showcase.workload.contexa.probe;

import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.std.rag.service.BehaviorDocumentRetentionScheduler;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.workload.contexa.ContexaWorkloadApplication;
import io.contexa.showcase.workload.contexa.inbox.DemoInboxEmailService;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Measures real security decisions of control D with the configured chat model: fresh principals, the real login and
 * one-time code flow, one protected request each, and the engine's own observation rows. Nothing is stubbed.
 * <p>
 * Opt-in because it spends model credit: tag live-llm, run with the liveLlmTest task and OPENAI_API_KEY set.
 * Properties: showcase.live.principals (default 10) and showcase.live.output (directory of the JSON report).
 */
@Tag("live-llm")
@EnabledIfEnvironmentVariable(named = "OPENAI_API_KEY", matches = ".+")
@Testcontainers(disabledWithoutDocker = true)
@ExtendWith(OutputCaptureExtension.class)
@SpringBootTest(classes = {ContexaWorkloadApplication.class, ProbeEndpoints.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class LiveDecisionMeasurementTest {

    private static final String SIGNING_KEY = ProbeDatabase.randomKey();
    private static final Duration ANALYSIS_TIMEOUT = Duration.ofMinutes(5);

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        ProbeDatabase.register(registry, SIGNING_KEY);
    }

    @LocalServerPort
    private int port;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private DemoInboxEmailService inbox;

    @Autowired
    private InternalContextSigner signer;

    @Autowired
    @Qualifier("contexaJdbcTemplate")
    private JdbcTemplate engineJdbc;

    @Value("${spring.ai.openai.chat.options.model}")
    private String chatModel;

    @Autowired
    private VectorStore vectorStore;

    @Autowired
    private UnifiedVectorService unifiedVectorService;

    @Autowired
    private BehaviorDocumentRetentionScheduler retentionScheduler;

    @Autowired
    @Qualifier("jdbcTemplate")
    private JdbcTemplate vectorJdbc;

    @Test
    void measureDecisionsOfFreshPrincipals() throws Exception {
        int principals = Integer.getInteger("showcase.live.principals", 10);
        Path output = Path.of(System.getProperty("showcase.live.output", "build/live-llm"));
        ProbeRuns runs = new ProbeRuns(users, passwordEncoder, inbox, signer, port);
        Instant startedAt = Instant.now();

        List<String> requestIds = new ArrayList<>();
        for (int index = 1; index <= principals; index++) {
            ProbeClient client = runs.newRun();
            runs.signIn(client);
            ProbeClient.Call call = client.call("GET", "/probe/documents/live-" + index);
            HttpResponse<String> response = call.send();
            assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
            requestIds.add(call.requestId());
        }

        List<Map<String, Object>> rows = awaitObservations(requestIds);
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("startedAt", startedAt.toString());
        report.put("finishedAt", Instant.now().toString());
        report.put("chatModel", chatModel);
        report.put("principals", principals);
        report.put("observed", rows.size());
        report.put("finalAction", countBy(rows, "final_action"));
        report.put("technicalFallback", countBy(rows, "technical_fallback"));
        report.put("fallbackCategory", countBy(rows, "fallback_category"));
        report.put("fallbackReason", countBy(rows, "fallback_reason"));
        report.put("rows", rows);
        report.put("evidence", evidence(requestIds));
        Files.createDirectories(output);
        Path file = output.resolve("decisions-" + startedAt.toEpochMilli() + ".json");
        ProbeRuns.JSON.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), report);

        assertThat(rows).as("every protected request leaves an observation row (report " + file + ")")
                .hasSize(principals);
    }

    /**
     * The engine filters personal RAG documents by user name. A valid name with an apostrophe must not break that
     * search. Each principal runs alone so the vector search errors logged during its analysis belong to it.
     */
    @Test
    void personalRagSearchWorksForUserNamesWithAnApostrophe(CapturedOutput output) throws Exception {
        Path reportDirectory = Path.of(System.getProperty("showcase.live.output", "build/live-llm"));
        ProbeRuns runs = new ProbeRuns(users, passwordEncoder, inbox, signer, port);
        Map<String, Object> report = new LinkedHashMap<>();
        for (String label : List.of("plain", "o'brien")) {
            ProbeClient client = runs.newRun(label);
            runs.signIn(client);
            int logStart = output.getOut().length();
            ProbeClient.Call call = client.call("GET", "/probe/documents/rag-" + label.length());
            assertThat(call.send().statusCode()).isEqualTo(200);
            List<Map<String, Object>> rows = awaitObservations(List.of(call.requestId()));
            String logs = output.getOut().substring(logStart);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("userName", client.run().username());
            result.put("observed", rows.size());
            result.put("finalAction", rows.isEmpty() ? null : rows.get(0).get("final_action"));
            result.put("vectorSearchFailures", countOccurrences(logs, "similarity search failed"));
            report.put(label, result);
        }
        Files.createDirectories(reportDirectory);
        Path file = reportDirectory.resolve("rag-apostrophe-" + Instant.now().toEpochMilli() + ".json");
        ProbeRuns.JSON.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), report);

        assertThat(report).as("report " + file).allSatisfy((label, result) ->
                assertThat(((Map<?, ?>) result).get("vectorSearchFailures")).as(label).isEqualTo(0));
    }

    /**
     * On the real pgvector store: a user filter with an apostrophe matches that user's documents, and the behaviour
     * retention removes only behaviour documents older than the retention period (default 90 days).
     */
    @Test
    void vectorFiltersMatchApostropheNamesAndRetentionRemovesOnlyExpiredBehaviour() {
        String marker = "probe-" + UUID.randomUUID();
        String user = "v-" + marker + "-o'brien";
        String recent = LocalDateTime.now().minusDays(10).toString();
        String expired = LocalDateTime.now().minusDays(120).toString();
        vectorStore.add(List.of(
                new Document("recent behaviour " + marker,
                        Map.of("documentType", "behavior", "userId", user, "timestamp", recent, "probeMarker", marker)),
                new Document("expired behaviour " + marker,
                        Map.of("documentType", "behavior", "userId", user, "timestamp", expired, "probeMarker", marker)),
                new Document("expired threat " + marker,
                        Map.of("documentType", "threat", "userId", user, "timestamp", expired, "probeMarker", marker))));

        List<Document> found = unifiedVectorService.searchSimilar(SearchRequest.builder()
                .query("behaviour " + marker).topK(10).similarityThreshold(0.0)
                .filterExpression(new FilterExpressionBuilder().eq("userId", user).build())
                .build());
        assertThat(found).hasSize(3);

        retentionScheduler.deleteExpiredBehaviorDocuments();

        List<String> remaining = vectorJdbc.queryForList(
                "select content from vector_store where metadata->>'probeMarker' = ? order by content", String.class, marker);
        assertThat(remaining).containsExactly("expired threat " + marker, "recent behaviour " + marker);
    }

    private static int countOccurrences(String text, String token) {
        int count = 0;
        for (int index = text.indexOf(token); index >= 0; index = text.indexOf(token, index + token.length())) {
            count++;
        }
        return count;
    }

    private List<Map<String, Object>> awaitObservations(Collection<String> requestIds) throws InterruptedException {
        String placeholders = requestIds.stream().map(id -> "?").collect(Collectors.joining(","));
        String sql = "select request_id, user_id, final_action, proposed_action, llm_decision_present, parser_failure, "
                + "technical_fallback, timeout_failure, failure_type, fallback_category, fallback_reason, llm_latency_ms, "
                + "created_at::text as created_at from ai_security_decision_observation where request_id in ("
                + placeholders + ") order by created_at";
        Instant deadline = Instant.now().plus(ANALYSIS_TIMEOUT);
        List<Map<String, Object>> rows = List.of();
        while (Instant.now().isBefore(deadline)) {
            rows = engineJdbc.queryForList(sql, requestIds.toArray());
            if (rows.size() >= requestIds.size()) {
                break;
            }
            Thread.sleep(2000);
        }
        return rows;
    }

    /** Prompt facts and decision of each request, from the sealed evidence package the engine stores. */
    private List<Map<String, Object>> evidence(Collection<String> requestIds) {
        String placeholders = requestIds.stream().map(id -> "?").collect(Collectors.joining(","));
        List<Map<String, Object>> packages = engineJdbc.queryForList(
                "select correlation_id, decision_json, user_prompt_text, prompt_execution_metadata_json "
                        + "from sealed_evidence_package where correlation_id in (" + placeholders + ")",
                requestIds.toArray());
        List<Map<String, Object>> evidence = new ArrayList<>();
        for (Map<String, Object> row : packages) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("requestId", row.get("correlation_id"));
            item.put("decision", row.get("decision_json"));
            item.put("promptFacts", factLines(String.valueOf(row.get("user_prompt_text"))));
            item.put("executionMetadata", row.get("prompt_execution_metadata_json"));
            evidence.add(item);
        }
        return evidence;
    }

    private static List<String> factLines(String prompt) {
        return prompt.lines()
                .map(String::trim)
                .filter(line -> line.startsWith("Rag") || line.contains("Baseline") || line.startsWith("Authorization")
                        || line.startsWith("Sensitivity") || line.startsWith("MfaVerified")
                        || line.startsWith("VerificationRequired"))
                .toList();
    }

    private static Map<String, Long> countBy(List<Map<String, Object>> rows, String column) {
        return rows.stream().collect(Collectors.groupingBy(
                row -> String.valueOf(row.get(column)), TreeMap::new, Collectors.counting()));
    }
}
