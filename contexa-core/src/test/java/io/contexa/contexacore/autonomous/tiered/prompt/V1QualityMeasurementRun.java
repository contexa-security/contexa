package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.tiered.strategy.SealedDecisionReplayStrategy;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.LLMOperations;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.pipeline.executor.UniversalPipelineExecutor;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionResponseProcessor;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionV1OutputInspector;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionV21OutputInspector;
import io.contexa.contexacore.std.pipeline.step.ContextRetrievalStep;
import io.contexa.contexacore.std.pipeline.step.LLMExecutionStep;
import io.contexa.contexacore.std.pipeline.step.PostprocessingStep;
import io.contexa.contexacore.std.pipeline.step.PreprocessingStep;
import io.contexa.contexacore.std.pipeline.step.PromptGenerationStep;
import io.contexa.contexacore.std.pipeline.step.ResponseParsingStep;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayInputs;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.MessageType;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.BufferedWriter;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Plan 1-8 (local measurement tool, not shipped): every labelled case is replayed as a sealed decision (plan 2.5: the
 * sealed decision replay, the same input with only the bundle changed) through the engine's own first-layer request
 * options, prompt template and pipeline (prompt generation, the execution step with its retries, checks and
 * fallbacks, response parsing and post-processing), the model call going to the local model. Each answer is a line of
 * the results file; a run that stops goes on from what the file holds. It runs only when V1_MEASURE is set.
 */
@EnabledIfEnvironmentVariable(named = "V1_MEASURE", matches = ".+")
class V1QualityMeasurementRun {

    private static final ObjectMapper JSON = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .findAndRegisterModules();
    private static final Pattern FACT_LABEL = Pattern.compile("\\[([A-Z]\\d+)]");
    /**
     * The measurement's own call limit: the engine's (90 s, recorded per call) cut answers of this GPU shared by two
     * calls for its speed, not for the bundle, so the comparison does not take it; the calls past it are counted apart.
     */
    private static final long CALL_LIMIT_MS = Long.parseLong(env("V1_MEASURE_CALL_LIMIT_MS", "600000"));
    private static final int NUM_CTX = Integer.parseInt(env("V1_MEASURE_NUM_CTX", "16384"));
    private static final Pattern FINDING = Pattern.compile("([A-Z][A-Z_]+) ([A-Z]\\d+) \\(");

    @Test
    void measure() throws Exception {
        // The golden inputs were sealed on an engine in UTC; the replay draws them in the same zone.
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        String server = env("V1_MEASURE_OLLAMA", "http://localhost:11435");
        String model = env("V1_MEASURE_MODEL", "qwen3:8b");
        int repeats = Integer.parseInt(env("V1_MEASURE_REPEATS", "3"));
        int workers = Integer.parseInt(env("V1_MEASURE_WORKERS", "2"));
        Path out = Path.of(env("V1_MEASURE_OUT", "build/v1-measure/results.jsonl"));
        Set<String> onlyCases = set(env("V1_MEASURE_CASES", ""));
        Set<String> onlyBundles = set(env("V1_MEASURE_BUNDLES", ""));
        Files.createDirectories(out.toAbsolutePath().getParent());
        Set<String> done = done(out);

        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        List<V1MeasurementCases.Case> cases = V1MeasurementCases.build(golden).stream()
                .filter(item -> onlyCases.isEmpty() || onlyCases.contains(item.key())).toList();
        List<SecurityDecisionPromptBundles.Bundle> bundles = SecurityDecisionPromptBundles.ALL.stream()
                .filter(bundle -> onlyBundles.isEmpty() || onlyBundles.contains(bundle.version())).toList();
        List<Runnable> tasks = new ArrayList<>();
        AtomicInteger written = new AtomicInteger();
        try (BufferedWriter writer = Files.newBufferedWriter(out, StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                StandardOpenOption.APPEND)) {
            for (int run = 1; run <= repeats; run++) {
                for (V1MeasurementCases.Case item : cases) {
                    for (SecurityDecisionPromptBundles.Bundle bundle : bundles) {
                        String key = bundle.version() + "|" + item.key() + "|" + run;
                        if (done.contains(key)) {
                            continue;
                        }
                        int runNo = run;
                        tasks.add(() -> {
                            Map<String, Object> result = answer(bundle, item, runNo, server, model);
                            synchronized (writer) {
                                try {
                                    writer.write(JSON.writeValueAsString(result));
                                    writer.newLine();
                                    writer.flush();
                                }
                                catch (IOException exception) {
                                    throw new IllegalStateException(exception);
                                }
                                System.out.println("[v1-measure] " + written.incrementAndGet() + "/" + tasks.size()
                                        + " " + key + " " + result.get("action") + " " + result.get("elapsedMs") + "ms");
                            }
                        });
                    }
                }
            }
            ExecutorService pool = Executors.newFixedThreadPool(workers);
            List<Future<?>> futures = new ArrayList<>();
            tasks.forEach(task -> futures.add(pool.submit(task)));
            for (Future<?> future : futures) {
                future.get();
            }
            pool.shutdown();
            pool.awaitTermination(1, TimeUnit.MINUTES);
        }
    }

    /** One replay of the case with the bundle, and what came out of it. */
    private static Map<String, Object> answer(SecurityDecisionPromptBundles.Bundle bundle, V1MeasurementCases.Case item,
                                              int run, String server, String model) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("bundle", bundle.version());
        result.put("case", item.key());
        result.put("kind", item.kind());
        result.put("expected", item.expected());
        result.put("allowed", item.allowed());
        result.put("expectedHypothesis", item.hypothesis());
        result.put("run", run);
        long started = System.nanoTime();
        OllamaClient client = new OllamaClient(server, model);
        try {
            TieredStrategyProperties properties = new TieredStrategyProperties();
            SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                    new SecurityDecisionPromptSections(new SecurityEventEnricher(), properties,
                            event -> Optional.empty(), new PromptContextComposer(), null, null, null));
            SecurityZeroTrustProperties zeroTrust = new SecurityZeroTrustProperties();
            JsonNode learning = item.input().path("learningEvidence");
            SealedDecisionReplayStrategy strategy = new SealedDecisionReplayStrategy(template, pipeline(template, client),
                    new BaselineLearningService(null, zeroTrust).readingFrom(new SealedDecisionReplayInputs.SealedBaselines(
                            vector(learning.path("personalBaseline")), vector(learning.path("organizationBaseline")))),
                    properties, StructuredOutputCapabilityRegistry.defaultRegistry(),
                    SealedDecisionReplayStrategy.FIRST_LAYER);
            strategy.setModelSelectionStrategy(() -> null);
            strategy.setMinimumActionSettings(zeroTrust.getMinimumAction().toRules(),
                    zeroTrust.getMinimumAction().getMode().name());
            SealedDecisionReplayInputs inputs = SealedDecisionReplayInputs.of(sealed(item.input()),
                    SealedDecisionReplayInputs.REPLAY_ID_PREFIX + UUID.randomUUID(), JSON,
                    new CanonicalSecurityContextSerializer(JSON));
            SecurityDecisionResponse response = strategy.replay(inputs, bundle.version(), Duration.ofMinutes(10));
            Map<String, Object> metadata = response != null ? response.getAllMetadata() : Map.of();
            String action = response != null && response.getAction() != null
                    ? response.getAction().trim().toUpperCase() : null;
            result.put("action", action);
            result.put("correct", action != null && item.allowed().contains(action));
            result.put("modelLess", Boolean.TRUE.equals(metadata.get("securityDecisionParsingFallbackApplied")));
            result.put("parseFailure", metadata.get("securityDecisionParseFailureCategory"));
            result.put("contractFallback", metadata.get("securityDecisionContractFallbackAction"));
            result.put("failure", metadata.get("securityDecisionRawExecutionFailureMessage"));
            result.put("retried", Boolean.TRUE.equals(metadata.get("securityDecisionOutputRetryAttempted")));
            result.put("retryReason", metadata.get("securityDecisionOutputRetryReason"));
            result.put("retrySucceeded", metadata.get("securityDecisionOutputRetrySucceeded"));
            result.put("unresolved", metadata.get(SecurityDecisionV21OutputInspector.UNRESOLVED_FINDINGS));
            result.put("ruleBreach", metadata.get(SecurityDecisionV1OutputInspector.V1_RULE_BREACH));
            result.put("hypothesis", mostLikely(metadata.get(SecurityDecisionV21OutputInspector.HYPOTHESES)));
            result.put("reason", response != null ? response.getReasoning() : null);
            List<SecurityDecisionOutputContract.Citation> codes = response != null && response.getReasonCodes() != null
                    ? response.getReasonCodes() : List.of();
            result.put("reasonCodes", codes.stream().map(code -> code.code() + ":" + code.fact()).toList());
            result.put("evidenceRefs", response != null ? response.getEvidenceRefs() : null);
            Object userPrompt = inputs.event().getMetadata().get(PromptRuntimeTelemetrySupport.FIRST_PASS_USER_PROMPT);
            result.put("citations", citations(codes, userPrompt instanceof String text ? text : null,
                    metadata.get(SecurityDecisionV21OutputInspector.UNRESOLVED_FINDINGS)));
            String dump = System.getenv("V1_MEASURE_DUMP");
            if (dump != null && !dump.isBlank()) {
                Path directory = Path.of(dump.trim());
                Files.createDirectories(directory);
                Files.writeString(directory.resolve(bundle.version() + "_" + item.key() + "_" + run + ".txt"),
                        "--- user ---\n" + userPrompt + "\n--- raw ---\n" + metadata.get("securityDecisionRawOutput")
                                + "\n--- retry raw ---\n" + metadata.get("securityDecisionRetryRawOutput"),
                        StandardCharsets.UTF_8);
            }
            result.put("calls", client.calls());
            result.put("promptTokens", client.promptTokens());
            result.put("outputTokens", client.outputTokens());
            result.put("finishReasons", client.finishReasons());
            result.put("truncatedPrompts", client.truncatedPrompts());
            result.put("callLimitsMs", client.callLimits());
            result.put("callMs", client.callMillis());
        }
        catch (RuntimeException | IOException exception) {
            result.put("action", null);
            result.put("correct", false);
            result.put("modelLess", true);
            result.put("failure", "REPLAY " + exception.getClass().getSimpleName() + ": " + exception.getMessage());
        }
        result.put("elapsedMs", Duration.ofNanos(System.nanoTime() - started).toMillis());
        return result;
    }

    /** The engine's pipeline with the local model behind its execution step. */
    private static PipelineOrchestrator pipeline(SecurityDecisionStandardPromptTemplate template, OllamaClient client) {
        PromptGenerator promptGenerator = new PromptGenerator(List.of(template));
        promptGenerator.registerTemplate(SecurityDecisionRequest.TEMPLATE_TYPE.name(), template);
        return new PipelineOrchestrator(List.of(new UniversalPipelineExecutor(
                new ContextRetrievalStep(new ContextRetrieverRegistry(new NoContextRetriever())),
                new PreprocessingStep(),
                new PromptGenerationStep(promptGenerator),
                new LLMExecutionStep(client),
                null,
                new ResponseParsingStep(),
                new PostprocessingStep(Optional.of(List.of(new SecurityDecisionResponseProcessor()))))));
    }

    /** How many past records of a case the similar cases are made from; each gives two similar cases. */
    private static final int SIMILAR_CASE_SOURCES = 3;

    /**
     * The similarity search's answer for a case, which the sealed golden inputs do not keep (D3 measurement limit): from
     * its first past records, the same work by another member of the organization and the same work on another target
     * of the same family by the user. Each keeps the outcome of the record it comes from. Only a bundle with the
     * similarity search draws them; the others read the exact past records as before.
     */
    private static JsonNode withSimilarCases(JsonNode ragResults) {
        JsonNode related = ragResults.path("relatedDocuments");
        if (!(ragResults instanceof ObjectNode results) || !related.isArray() || related.isEmpty()) {
            return ragResults;
        }
        ObjectNode copy = results.deepCopy();
        ArrayNode similar = copy.putArray(SimilarCases.SEALED_KEY);
        for (int index = 0; index < Math.min(SIMILAR_CASE_SOURCES, related.size()); index++) {
            JsonNode document = related.get(index);
            similar.add(peerRecord(document));
            similar.add(otherTargetRecord(document));
        }
        return copy;
    }

    /** The record as another member of the same organization did it, authorized by the organization scope. */
    private static ObjectNode peerRecord(JsonNode document) {
        ObjectNode peer = document.deepCopy();
        String user = document.path("userId").asText("user");
        String peerUser = "peer-" + user;
        peer.put("id", document.path("id").asText() + "-peer");
        peer.put("eventId", document.path("eventId").asText() + "-peer");
        peer.put("userId", peerUser);
        peer.put("accessScope", "ORGANIZATION");
        peer.put("authorization", "ALLOWED_ORGANIZATION_SCOPE");
        peer.put("retrievalPolicy", document.path("retrievalPolicy").asText("").replace("user=" + user, "user=" + peerUser));
        return peer;
    }

    /** The record on another target of the same family, by the same user. */
    private static ObjectNode otherTargetRecord(JsonNode document) {
        ObjectNode other = document.deepCopy();
        String path = document.path("requestPath").asText("");
        int last = path.lastIndexOf('/');
        // The target is the identifier segment: before an action segment (/documents/{key}/download), else the last.
        String otherPath = path.matches(".*/[^/]*\\d[^/]*/[^/\\d]+$")
                ? path.substring(0, last) + "-B" + path.substring(last)
                : path + "-B";
        other.put("id", document.path("id").asText() + "-other");
        other.put("eventId", document.path("eventId").asText() + "-other");
        other.put("requestPath", otherPath);
        other.put("sameTarget", "no");
        other.put("textPreview", document.path("textPreview").asText("").replace(path, otherPath));
        return other;
    }

    /** The golden case (or its variant) as the sealed package it was taken from. */
    private static SealedEvidencePackage sealed(JsonNode input) {
        SealedEvidencePackage sealed = new SealedEvidencePackage();
        sealed.setPackageId(input.path("source").path("packageId").asText(null));
        sealed.setCorrelationId(input.path("requestFacts").path("requestId").asText(null));
        sealed.setCanonicalContextJson(input.path("canonicalContext").toString());
        sealed.setRequestFactsJson(input.path("requestFacts").toString());
        sealed.setAuthStateJson(input.path("authState").toString());
        sealed.setBaselineSnapshotJson(input.path("baselineSnapshot").toString());
        sealed.setRagResultsJson(withSimilarCases(input.path("ragResults")).toString());
        JsonNode denied = input.path("pastDeniedDecisions");
        if (denied.isArray()) {
            ObjectNode execution = JSON.createObjectNode();
            execution.putObject("supplementalMetadata").set(PromptExecutionMetadata.PROMPT_PAST_DENIED_DECISIONS, denied);
            sealed.setPromptExecutionMetadataJson(execution.toString());
        }
        return sealed;
    }

    private static BaselineVector vector(JsonNode node) {
        return node.isMissingNode() || node.isNull() ? null : JSON.convertValue(node, BaselineVector.class);
    }

    /**
     * The cited facts, how many of them are lines of the prompt the answer was given, and how many of those the engine's
     * check still named as not saying what the code claims (each "CODE FACT (" of its unresolved findings).
     */
    private static Map<String, Object> citations(List<SecurityDecisionOutputContract.Citation> codes, String userPrompt,
                                                 Object unresolved) {
        Set<String> labels = new HashSet<>();
        if (userPrompt != null) {
            Matcher matcher = FACT_LABEL.matcher(userPrompt);
            while (matcher.find()) {
                labels.add(matcher.group(1));
            }
        }
        int cited = 0;
        int onALine = 0;
        for (SecurityDecisionOutputContract.Citation code : codes) {
            if (code.fact() == null || code.fact().isBlank()) {
                continue;
            }
            for (String fact : code.fact().split("[,\\s]+")) {
                if (fact.isBlank()) {
                    continue;
                }
                cited++;
                if (labels.contains(fact.trim())) {
                    onALine++;
                }
            }
        }
        Set<String> citedPairs = new HashSet<>();
        for (SecurityDecisionOutputContract.Citation code : codes) {
            if (code.fact() != null) {
                for (String fact : code.fact().split("[,\\s]+")) {
                    citedPairs.add(code.code() + " " + fact.trim());
                }
            }
        }
        int named = 0;
        if (unresolved != null) {
            Matcher finding = FINDING.matcher(String.valueOf(unresolved));
            Set<String> seen = new HashSet<>();
            while (finding.find()) {
                String pair = finding.group(1) + " " + finding.group(2);
                if (citedPairs.contains(pair) && seen.add(pair)) {
                    named++;
                }
            }
        }
        Map<String, Object> citations = new LinkedHashMap<>();
        citations.put("cited", cited);
        citations.put("onALine", onALine);
        citations.put("namedByTheCheck", named);
        citations.put("promptHasFactIds", !labels.isEmpty());
        return citations;
    }

    /** The explanation the answer weighed as most likely, or null. */
    private static String mostLikely(Object hypotheses) {
        if (!(hypotheses instanceof List<?> list)) {
            return null;
        }
        for (Object entry : list) {
            if (entry instanceof Map<?, ?> map && "MOST_LIKELY".equals(String.valueOf(map.get("assessment")))) {
                return String.valueOf(map.get("id"));
            }
        }
        return null;
    }

    private static Set<String> done(Path out) throws IOException {
        Set<String> done = new HashSet<>();
        if (!Files.exists(out)) {
            return done;
        }
        for (String line : Files.readAllLines(out, StandardCharsets.UTF_8)) {
            if (line.isBlank()) {
                continue;
            }
            JsonNode node = JSON.readTree(line);
            done.add(node.path("bundle").asText() + "|" + node.path("case").asText() + "|" + node.path("run").asInt());
        }
        return done;
    }

    private static String env(String name, String otherwise) {
        String value = System.getenv(name);
        return value != null && !value.isBlank() ? value.trim() : otherwise;
    }

    private static Set<String> set(String values) {
        Set<String> set = new HashSet<>();
        for (String value : values.split(",")) {
            if (!value.isBlank()) {
                set.add(value.trim());
            }
        }
        return set;
    }

    /** A replay gives the past records itself; the pipeline's own retrieval finds none. */
    private static final class NoContextRetriever extends ContextRetriever {

        private NoContextRetriever() {
            super((VectorStore) null, new ContexaRagProperties());
        }

        @Override
        public ContextRetrievalResult retrieveContext(AIRequest<? extends DomainContext> request) {
            return new ContextRetrievalResult("", List.<Document>of(), Map.of("documentsFound", 0));
        }
    }

    /**
     * The local model behind the engine's model client: the chat endpoint with the call's sampling options, its output
     * limit and its call limit, and the finish reason the execution step reads.
     */
    private static final class OllamaClient implements LLMClient, LLMOperations {

        private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

        private final String server;
        private final String model;
        private final AtomicInteger calls = new AtomicInteger();
        private final AtomicInteger promptTokens = new AtomicInteger();
        private final AtomicInteger outputTokens = new AtomicInteger();
        private final AtomicInteger truncatedPrompts = new AtomicInteger();
        private final List<String> finishReasons = new ArrayList<>();
        private final List<Long> callLimits = new ArrayList<>();
        private final List<Long> callMillis = new ArrayList<>();

        private OllamaClient(String server, String model) {
            this.server = server;
            this.model = model;
        }

        int calls() {
            return calls.get();
        }

        int promptTokens() {
            return promptTokens.get();
        }

        int outputTokens() {
            return outputTokens.get();
        }

        int truncatedPrompts() {
            return truncatedPrompts.get();
        }

        synchronized List<String> finishReasons() {
            return List.copyOf(finishReasons);
        }

        synchronized List<Long> callLimits() {
            return List.copyOf(callLimits);
        }

        synchronized List<Long> callMillis() {
            return List.copyOf(callMillis);
        }

        @Override
        public Mono<String> execute(ExecutionContext context) {
            Object limit = context.getMetadata().get(ExecutionContext.CALL_TIMEOUT_MS);
            synchronized (this) {
                callLimits.add(limit instanceof Number millis ? millis.longValue() : -1L);
            }
            Mono<String> call = Mono.fromCallable(() -> {
                long started = System.nanoTime();
                try {
                    return chat(context.getPrompt(), context.getTemperature(), context.getSeed(),
                            context.getMaxTokens(), context);
                }
                finally {
                    synchronized (this) {
                        callMillis.add(Duration.ofNanos(System.nanoTime() - started).toMillis());
                    }
                }
            });
            // The blocking call runs apart, so that the limit can end the wait.
            return call.subscribeOn(Schedulers.boundedElastic()).timeout(Duration.ofMillis(CALL_LIMIT_MS));
        }

        @Override
        public Flux<String> stream(ExecutionContext context) {
            return execute(context).flux();
        }

        @Override
        public <T> Mono<T> executeEntity(ExecutionContext context, Class<T> targetType) {
            return Mono.error(new UnsupportedOperationException("A security decision is read raw"));
        }

        @Override
        public Mono<String> call(Prompt prompt) {
            return Mono.fromCallable(() -> chat(prompt, 0.0d, 1, null, null));
        }

        @Override
        public <T> Mono<T> entity(Prompt prompt, Class<T> targetType) {
            return Mono.error(new UnsupportedOperationException("A security decision is read raw"));
        }

        @Override
        public Flux<String> stream(Prompt prompt) {
            return call(prompt).flux();
        }

        private String chat(Prompt prompt, Double temperature, Integer seed, Integer maxTokens, ExecutionContext context)
                throws Exception {
            calls.incrementAndGet();
            ObjectNode body = JSON.createObjectNode();
            body.put("model", model);
            body.put("stream", false);
            body.put("think", false);
            ArrayNode messages = body.putArray("messages");
            for (Message message : prompt.getInstructions()) {
                ObjectNode entry = messages.addObject();
                entry.put("role", message.getMessageType() == MessageType.SYSTEM ? "system"
                        : message.getMessageType() == MessageType.ASSISTANT ? "assistant" : "user");
                entry.put("content", message.getText());
            }
            ObjectNode options = body.putObject("options");
            // The server's default context (4,096 tokens) cuts a decision prompt of about 6,000 tokens.
            options.put("num_ctx", NUM_CTX);
            options.put("temperature", temperature != null ? temperature : 0.0d);
            options.put("seed", seed != null ? seed : 1);
            if (maxTokens != null) {
                options.put("num_predict", maxTokens);
            }
            HttpRequest request = HttpRequest.newBuilder(URI.create(server + "/api/chat"))
                    .timeout(Duration.ofMinutes(10))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body), StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) {
                throw new IllegalStateException("Model server answered " + response.statusCode() + ": "
                        + response.body());
            }
            JsonNode answer = JSON.readTree(response.body());
            int promptEvalCount = answer.path("prompt_eval_count").asInt();
            if (promptEvalCount >= NUM_CTX - answer.path("eval_count").asInt() - 8) {
                truncatedPrompts.incrementAndGet();
            }
            promptTokens.addAndGet(promptEvalCount);
            outputTokens.addAndGet(answer.path("eval_count").asInt());
            String finishReason = answer.path("done_reason").asText("");
            synchronized (this) {
                finishReasons.add(finishReason);
            }
            if (context != null && !finishReason.isBlank()) {
                context.getMetadata().put("providerFinishReason", finishReason);
            }
            return answer.path("message").path("content").asText("");
        }
    }
}
