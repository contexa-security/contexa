package io.contexa.contexaiam.admin.promptquality.inspection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityEventProcessor;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.inference.ContextCoverageEvaluator;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.context.registry.InMemoryResourceContextRegistry;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.prompt.AgentLineValues;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageAssembler;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayInputs;
import io.contexa.contexaiam.admin.promptquality.evidence.JdbcSealedEvidencePackageRepository;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.tools.ToolProvider;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Q-11 (PR-59, PR-64): what a request leaves in the rows PostgreSQL keeps, read as measurement M11 reads them: the whole
 * row as text. The request goes through what it goes through in an application: the publisher makes its event from the
 * servlet request and the protected call, the agent takes it from the batch, the canonical context is drawn from it, and
 * the assembler and the observation writer store it. Only the model is left out. A test of one writer sees the columns
 * that writer names; the canonical context copies every metadata key of the event, and the observation keeps that copy
 * too, so a value any stage puts in the metadata reaches both tables without either writer naming it.
 */
@Timeout(value = 90, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class StoredRecordsOfARequestTest {

    private static final String SESSION = "8E1F0A77C2D94B6E9A03D5C1B2E47F10";
    private static final String QUERY = "pin=RCSECRET1&newPwd=RCSECRET2&ssn=RCSECRET3&token=RCSECRET4";
    private static final List<String> SECRETS = List.of("RCSECRET1", "RCSECRET2", "RCSECRET3", "RCSECRET4");
    private static final String SEALED = "ctxa_sealed_evidence_package";
    private static final String OBSERVED = "ctxa_ai_security_decision_observation";
    private static final String CANONICAL_CONTEXT = "sealedEvidence.canonicalContext";
    private static final String CONTROLLER = """
            import io.contexa.contexacommon.annotation.Protectable;

            public class AccountController {

                @Protectable
                public void changePin(String pin, String newPwd, String ssn, String token, String projectKey) {
                }
            }
            """;

    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();
    private final SealedEvidencePromptTraceStore traceStore = new SealedEvidencePromptTraceStore();
    private final ExecutorService analysis = Executors.newCachedThreadPool();
    private final AtomicReference<Throwable> failure = new AtomicReference<>();
    private final CountDownLatch stored = new CountDownLatch(1);

    @TempDir
    Path classes;

    private PostgresTestDatabase database;
    private JdbcTemplate jdbc;
    private JdbcSealedEvidencePackageRepository repository;
    private SealedEvidencePackageIntegrity integrity;
    private SealedEvidencePackageAssembler assembler;
    private AiSecurityDecisionObservationWriter writer;
    private DefaultCanonicalSecurityContextProvider contexts;
    private SecurityPlaneAgent agent;
    private URLClassLoader compiled;
    private String sealedPrompt;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        InspectionSchema.sealedLinkedStatements().forEach(jdbc::execute);
        InspectionSchema.decisionObservationStatements().forEach(jdbc::execute);
        integrity = new SealedEvidencePackageIntegrity(HmacEvidenceSigner.of(Map.of("k1", Base64.getEncoder()
                .encodeToString("k1-0123456789abcdef0123456789abcd".getBytes())), null));
        repository = new JdbcSealedEvidencePackageRepository(jdbc);
        repository.setIntegrity(integrity);
        assembler = new SealedEvidencePackageAssembler(json, new CanonicalSecurityContextSerializer(json), integrity,
                traceStore);
        writer = new AiSecurityDecisionObservationWriter(() -> jdbc, json, "anthropic", "claude-haiku-5-5");
        contexts = new DefaultCanonicalSecurityContextProvider(new InMemoryResourceContextRegistry(),
                new ContextCoverageEvaluator());
    }

    @AfterEach
    void tearDown() throws Exception {
        RequestContextHolder.resetRequestAttributes();
        if (agent != null) {
            agent.shutdown();
        }
        analysis.shutdownNow();
        if (compiled != null) {
            compiled.close();
        }
        database.close();
    }

    @Test
    void aRequestLeavesNoLiveSessionIdAndNoSecretValueInTheRows() throws Exception {
        decide();

        assertThat(jdbc.queryForObject("select count(*) from " + SEALED, Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from " + OBSERVED, Long.class)).isEqualTo(1);
        assertThat(rowsHolding(SEALED, SESSION)).as("the session id in the seal").isZero();
        assertThat(rowsHolding(OBSERVED, SESSION)).as("the session id in the observation").isZero();
        for (String secret : SECRETS) {
            assertThat(rowsHolding(SEALED, secret)).as(secret + " in the seal").isZero();
            assertThat(rowsHolding(OBSERVED, secret)).as(secret + " in the observation").isZero();
        }
    }

    /** What a decision reads stays: which session, what was called and with which argument names and plain facts. */
    @Test
    void theRecordsKeepWhatADecisionReads() throws Exception {
        decide();

        SealedEvidencePackage sealed = repository.findByCorrelationId(correlationId()).orElseThrow();
        String reference = RequestFactRedaction.sessionReference(SESSION);
        JsonNode attributes = json.readTree(sealed.getCanonicalContextJson()).path("attributes");
        assertThat(attributes.path("invocationArguments").asText())
                .isEqualTo("pin=<hidden>; newPwd=<hidden>; ssn=<hidden>; token=<hidden>; projectKey=GB-500");
        assertThat(attributes.path("analysisKey").asText()).isEqualTo("alice|" + reference);
        assertThat(json.readTree(sealed.getCanonicalContextJson()).path("session").path("sessionId").asText())
                .isEqualTo(reference);
        assertThat(json.readTree(sealed.getRequestFactsJson()).path("queryString").asText())
                .isEqualTo("pin&newPwd&ssn&token");
        assertThat(sealedPrompt).as("the session line of the model's input").contains(reference);
        assertThat(AgentLineValues.callArguments(new CanonicalSecurityContextSerializer(json)
                .deserialize(sealed.getCanonicalContextJson()))).as("the call arguments line of a v21 prompt")
                .contains("projectKey=GB-500");
    }

    /** The seal stays whole and a replay reads what was sealed. */
    @Test
    void theSealHoldsAndAReplayReadsWhatWasSealed() throws Exception {
        decide();

        SealedEvidencePackage sealed = repository.findByCorrelationId(correlationId()).orElseThrow();
        assertThat(integrity.evaluate(sealed)).isEqualTo(SealedEvidencePackageIntegrity.Status.VERIFIED);
        SealedDecisionReplayInputs inputs = SealedDecisionReplayInputs.of(sealed, "replay-1", json,
                new CanonicalSecurityContextSerializer(json));
        assertThat(inputs.event().getSessionId()).isEqualTo(RequestFactRedaction.sessionReference(SESSION));
        assertThat(AgentLineValues.callArguments(inputs.canonicalContext())).contains("pin=<hidden>", "projectKey=GB-500");
    }

    private String correlationId() {
        return jdbc.queryForObject("select correlation_id from " + SEALED, String.class);
    }

    private long rowsHolding(String table, String value) {
        Long rows = jdbc.queryForObject("select count(*) from " + table + " t where position(? in t::text) > 0",
                Long.class, value);
        return rows == null ? 0 : rows;
    }

    /** The request as an application makes it, decided by the agent; the pipeline's stages after it store what it left. */
    private void decide() throws Exception {
        SecurityEvent event = eventOfTheRequest();
        assertThat(event.getSessionId()).as("the event keeps the live id for the session stores").isEqualTo(SESSION);

        SecurityMonitoringService monitor = mock(SecurityMonitoringService.class);
        SecurityEventProcessor pipeline = mock(SecurityEventProcessor.class);
        when(pipeline.process(any(SecurityEvent.class))).thenAnswer(call -> store(call.getArgument(0)));
        agent = new SecurityPlaneAgent(monitor, new InMemorySecurityContextDataStore(), mock(CentralAuditFacade.class),
                pipeline, new SecurityPlaneProperties(), analysis);
        agent.initialize();
        agent.start();
        ArgumentCaptor<SecurityMonitoringService.SecurityEventBatchProcessor> batches =
                ArgumentCaptor.forClass(SecurityMonitoringService.SecurityEventBatchProcessor.class);
        verify(monitor).setBatchProcessor(batches.capture());

        batches.getValue().processBatch(List.of(event));

        assertThat(stored.await(60, TimeUnit.SECONDS)).as("the pipeline stored the request").isTrue();
        assertThat(failure.get()).isNull();
    }

    private SecurityEvent eventOfTheRequest() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/rc/pin");
        request.setQueryString(QUERY);
        request.setSession(new MockHttpSession(null, SESSION));
        request.setRequestedSessionId(SESSION);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        MethodInvocation call = mock(MethodInvocation.class);
        when(call.getMethod()).thenReturn(protectedMethod());
        when(call.getArguments()).thenReturn(new Object[]{"RCSECRET1", "RCSECRET2", "RCSECRET3", "RCSECRET4", "GB-500"});
        ZeroTrustSpringEvent published = new ZeroTrustEventPublisher(mock(ApplicationEventPublisher.class),
                new TieredStrategyProperties()).buildMethodAuthorizationEvent(call,
                new UsernamePasswordAuthenticationToken("alice", "n/a"), true, null);
        return ZeroTrustSecurityEventConverter.convert(published);
    }

    /** The application's controller keeps its parameter names, as a Spring Boot build does; this module's classes do not. */
    private Method protectedMethod() throws Exception {
        Path source = Files.writeString(classes.resolve("AccountController.java"), CONTROLLER);
        int done = ToolProvider.getSystemJavaCompiler().run(null, null, null, "-parameters", "-proc:none", "-cp",
                System.getProperty("java.class.path"), "-d", classes.toString(), source.toString());
        assertThat(done).as("the controller compiles").isZero();
        compiled = new URLClassLoader(new URL[]{classes.toUri().toURL()}, getClass().getClassLoader());
        return compiled.loadClass("AccountController").getMethod("changePin", String.class, String.class, String.class,
                String.class, String.class);
    }

    /** The stages that keep the request: the context and the prompt drawn, the package sealed, the observation written. */
    private SecurityEventContext store(SecurityEvent event) {
        try {
            CanonicalSecurityContext context = contexts.resolve(event).orElseThrow();
            event.addMetadata(CANONICAL_CONTEXT, context);
            sealedPrompt = new PromptContextComposer().compose(context);
            SecurityDecisionContext drawn = mock(SecurityDecisionContext.class);
            when(drawn.getSecurityEvent()).thenReturn(event);
            when(drawn.getRelatedDocuments()).thenReturn(List.of());
            PromptGenerationResult prompt = mock(PromptGenerationResult.class);
            when(prompt.getSystemPrompt()).thenReturn("system prompt");
            when(prompt.getUserPrompt()).thenReturn(sealedPrompt);
            when(prompt.getRawSystemPrompt()).thenReturn("system prompt");
            when(prompt.getRawUserPrompt()).thenReturn(sealedPrompt);
            when(prompt.getMetadata()).thenReturn(Map.of());
            traceStore.capture(drawn, prompt);
            traceStore.complete(event);
            ProcessingResult result = ProcessingResult.builder().success(true).action(ZeroTrustAction.ALLOW.name())
                    .llmDecisionPresent(true).build();
            SecurityEventContext decided = new SecurityEventContext(event);
            decided.addMetadata("processingResult", result);
            repository.save(assembler.assemble(decided));
            writer.recordDecision(event, result, ZeroTrustAction.ALLOW);
            return decided;
        } catch (RuntimeException | Error thrown) {
            failure.set(thrown);
            throw thrown;
        } finally {
            stored.countDown();
        }
    }
}
