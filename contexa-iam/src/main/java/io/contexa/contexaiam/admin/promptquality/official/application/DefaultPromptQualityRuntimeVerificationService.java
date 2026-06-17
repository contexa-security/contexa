package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.adjudication.ScorecardResult;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePromptEvidenceBackfill;
import io.contexa.contexacore.verification.metric.OfficialContextHashStateResolver;
import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;
import io.contexa.contexacore.verification.replay.DeterministicReplayResult;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckResultView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationEventItemView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptPreflightService;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRequest;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationResult;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRuntime;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityAssuranceCaseService;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityCustomerSentencePolicy;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceCase;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceScope;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityIssue;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationExecutionStatus;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyFindingResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import io.contexa.contexaiam.admin.promptquality.official.application.support.AbstractPromptQualityRuntimeEvidenceSupport;
import io.contexa.contexaiam.admin.promptquality.official.process.NoopPromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessCodes;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessScope;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessStepSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.state.PromptQualityStateDimension;
import io.contexa.contexaiam.admin.promptquality.official.application.ProtectableResourceDescriptor;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityCertificateService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityCertificateService.MetricExecutionFailure;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityCertificateService.MetricRunEvidence;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityCertificateService.PromptQualityCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class DefaultPromptQualityRuntimeVerificationService
        extends AbstractPromptQualityRuntimeEvidenceSupport
        implements PromptQualityRuntimeVerificationService {

    private static final Logger log = LoggerFactory.getLogger(DefaultPromptQualityRuntimeVerificationService.class);
    private static final ZoneId KOREA_ZONE = ZoneId.of("Asia/Seoul");
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final Set<String> PASS_STATES = Set.of("SUCCESS", "PASS", "PASSED", "VERIFIED", "COMPLETED");

    private final SealedEvidencePackageQueryService lookupService;
    private final RuntimeEvidenceReplayService replayService;
    private final RuntimeEvidencePromptScorecardService promptScorecardService;
    private final OfficialSealedEvidenceVerificationRuntime officialSealedEvidenceVerificationRuntime;
    private final PromptQualityRuntimeCertificationPolicy certificationPolicy;
    private final PromptQualityProtectableResourceLookup resourceLookup;
    private final PromptQualityRuntimeCertificateIssuer certificateIssuer;
    private final PromptQualityOfficialMetricCatalog metricCatalog;
    private final PromptQualityAssuranceCaseService assuranceCaseService;
    private final RuntimeIssueDiagnosticService runtimeIssueDiagnosticService;
    private final PromptQualityMessageResolver messageResolver;
    private final RuntimeEvidencePromptConsistencyGate promptConsistencyGate;
    private final PromptQualityProcessRunService processRunService;
    private final OfficialVerificationOperatorSnapshotService operatorSnapshotService;
    private final OfficialVerificationExecutionLockService executionLockService;
    private final FinalPromptPreflightService finalPromptPreflightService;
    private final OfficialPromptQualityNarrativeCatalog narrativeCatalog = new OfficialPromptQualityNarrativeCatalog();

    public DefaultPromptQualityRuntimeVerificationService(
            SealedEvidencePackageQueryService lookupService,
            RuntimeEvidenceReplayService replayService,
            RuntimeEvidencePromptScorecardService promptScorecardService,
            OfficialSealedEvidenceVerificationRuntime officialSealedEvidenceVerificationRuntime,
            PromptQualityRuntimeCertificationPolicy certificationPolicy,
            PromptQualityProtectableResourceLookup resourceLookup,
            PromptQualityRuntimeCertificateIssuer certificateIssuer,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityAssuranceCaseService assuranceCaseService,
            RuntimeIssueDiagnosticService runtimeIssueDiagnosticService,
            ObjectMapper objectMapper) {
        this(lookupService,
                replayService,
                promptScorecardService,
                officialSealedEvidenceVerificationRuntime,
                certificationPolicy,
                resourceLookup,
                certificateIssuer,
                metricCatalog,
                assuranceCaseService,
                runtimeIssueDiagnosticService,
                null,
                objectMapper);
    }

    public DefaultPromptQualityRuntimeVerificationService(
            SealedEvidencePackageQueryService lookupService,
            RuntimeEvidenceReplayService replayService,
            RuntimeEvidencePromptScorecardService promptScorecardService,
            OfficialSealedEvidenceVerificationRuntime officialSealedEvidenceVerificationRuntime,
            PromptQualityRuntimeCertificationPolicy certificationPolicy,
            PromptQualityProtectableResourceLookup resourceLookup,
            PromptQualityRuntimeCertificateIssuer certificateIssuer,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityAssuranceCaseService assuranceCaseService,
            RuntimeIssueDiagnosticService runtimeIssueDiagnosticService,
            PromptQualityMessageResolver messageResolver,
            ObjectMapper objectMapper) {
        this(lookupService,
                replayService,
                promptScorecardService,
                officialSealedEvidenceVerificationRuntime,
                certificationPolicy,
                resourceLookup,
                certificateIssuer,
                metricCatalog,
                assuranceCaseService,
                runtimeIssueDiagnosticService,
                messageResolver,
                objectMapper,
                null);
    }

    public DefaultPromptQualityRuntimeVerificationService(
            SealedEvidencePackageQueryService lookupService,
            RuntimeEvidenceReplayService replayService,
            RuntimeEvidencePromptScorecardService promptScorecardService,
            OfficialSealedEvidenceVerificationRuntime officialSealedEvidenceVerificationRuntime,
            PromptQualityRuntimeCertificationPolicy certificationPolicy,
            PromptQualityProtectableResourceLookup resourceLookup,
            PromptQualityRuntimeCertificateIssuer certificateIssuer,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityAssuranceCaseService assuranceCaseService,
            RuntimeIssueDiagnosticService runtimeIssueDiagnosticService,
            PromptQualityMessageResolver messageResolver,
            ObjectMapper objectMapper,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate) {
        this(lookupService,
                replayService,
                promptScorecardService,
                officialSealedEvidenceVerificationRuntime,
                certificationPolicy,
                resourceLookup,
                certificateIssuer,
                metricCatalog,
                assuranceCaseService,
                runtimeIssueDiagnosticService,
                messageResolver,
                objectMapper,
                promptConsistencyGate,
                new NoopPromptQualityProcessRunService());
    }

    public DefaultPromptQualityRuntimeVerificationService(
            SealedEvidencePackageQueryService lookupService,
            RuntimeEvidenceReplayService replayService,
            RuntimeEvidencePromptScorecardService promptScorecardService,
            OfficialSealedEvidenceVerificationRuntime officialSealedEvidenceVerificationRuntime,
            PromptQualityRuntimeCertificationPolicy certificationPolicy,
            PromptQualityProtectableResourceLookup resourceLookup,
            PromptQualityRuntimeCertificateIssuer certificateIssuer,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityAssuranceCaseService assuranceCaseService,
            RuntimeIssueDiagnosticService runtimeIssueDiagnosticService,
            PromptQualityMessageResolver messageResolver,
            ObjectMapper objectMapper,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            PromptQualityProcessRunService processRunService) {
        this(lookupService,
                replayService,
                promptScorecardService,
                officialSealedEvidenceVerificationRuntime,
                certificationPolicy,
                resourceLookup,
                certificateIssuer,
                metricCatalog,
                assuranceCaseService,
                runtimeIssueDiagnosticService,
                messageResolver,
                objectMapper,
                promptConsistencyGate,
                null,
                processRunService,
                null);
    }

    public DefaultPromptQualityRuntimeVerificationService(
            SealedEvidencePackageQueryService lookupService,
            RuntimeEvidenceReplayService replayService,
            RuntimeEvidencePromptScorecardService promptScorecardService,
            OfficialSealedEvidenceVerificationRuntime officialSealedEvidenceVerificationRuntime,
            PromptQualityRuntimeCertificationPolicy certificationPolicy,
            PromptQualityProtectableResourceLookup resourceLookup,
            PromptQualityRuntimeCertificateIssuer certificateIssuer,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityAssuranceCaseService assuranceCaseService,
            RuntimeIssueDiagnosticService runtimeIssueDiagnosticService,
            PromptQualityMessageResolver messageResolver,
            ObjectMapper objectMapper,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            PromptQualityProcessRunService processRunService) {
        this(lookupService,
                replayService,
                promptScorecardService,
                officialSealedEvidenceVerificationRuntime,
                certificationPolicy,
                resourceLookup,
                certificateIssuer,
                metricCatalog,
                assuranceCaseService,
                runtimeIssueDiagnosticService,
                messageResolver,
                objectMapper,
                promptConsistencyGate,
                operatorSnapshotService,
                processRunService,
                null);
    }

    public DefaultPromptQualityRuntimeVerificationService(
            SealedEvidencePackageQueryService lookupService,
            RuntimeEvidenceReplayService replayService,
            RuntimeEvidencePromptScorecardService promptScorecardService,
            OfficialSealedEvidenceVerificationRuntime officialSealedEvidenceVerificationRuntime,
            PromptQualityRuntimeCertificationPolicy certificationPolicy,
            PromptQualityProtectableResourceLookup resourceLookup,
            PromptQualityRuntimeCertificateIssuer certificateIssuer,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityAssuranceCaseService assuranceCaseService,
            RuntimeIssueDiagnosticService runtimeIssueDiagnosticService,
            PromptQualityMessageResolver messageResolver,
            ObjectMapper objectMapper,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            PromptQualityProcessRunService processRunService,
            OfficialVerificationExecutionLockService executionLockService) {
        super(objectMapper, messageResolver);
        this.lookupService = lookupService;
        this.replayService = replayService;
        this.promptScorecardService = promptScorecardService;
        this.officialSealedEvidenceVerificationRuntime = officialSealedEvidenceVerificationRuntime;
        this.certificationPolicy = certificationPolicy;
        this.resourceLookup = resourceLookup;
        this.certificateIssuer = certificateIssuer;
        this.metricCatalog = metricCatalog;
        this.assuranceCaseService = assuranceCaseService;
        this.runtimeIssueDiagnosticService = runtimeIssueDiagnosticService;
        this.messageResolver = messageResolver;
        this.promptConsistencyGate = promptConsistencyGate == null
                ? new DefaultRuntimeEvidencePromptConsistencyGate(objectMapper, null, messageResolver)
                : promptConsistencyGate;
        this.processRunService = processRunService == null ? new NoopPromptQualityProcessRunService() : processRunService;
        this.operatorSnapshotService = operatorSnapshotService;
        this.executionLockService = executionLockService == null
                ? new NoopOfficialVerificationExecutionLockService()
                : executionLockService;
        this.finalPromptPreflightService = new FinalPromptPreflightService(objectMapper);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public RuntimeEvidenceVerificationRun verify(RuntimeEvidenceVerificationRequest request) {
        if (request == null || !StringUtils.hasText(request.packageId())) {
            throw new IllegalArgumentException(message(
                    "enterprise.pqa.runtimeVerification.error.packageId.required",
                    "Request evidence packageId is required."));
        }
        SealedEvidencePackage loadedPackage = lookupService.findByPackageId(request.packageId().trim())
                .orElseThrow(() -> new IllegalArgumentException(message(
                        "enterprise.pqa.runtimeVerification.error.packageId.notFound",
                        "Request evidence packageId was not found: {0}",
                        request.packageId())));
        SealedEvidencePackage pkg = prepareSealedPromptEvidencePackage(loadedPackage);
        String generatedAt = now();
        Map<String, Object> requestFacts = parseJson(pkg.getRequestFactsJson());
        Map<String, Object> authState = parseJson(pkg.getAuthStateJson());
        Map<String, Object> promptMetadata = parseJson(pkg.getPromptExecutionMetadataJson());
        Map<String, Object> decision = parseJson(pkg.getDecisionJson());
        String requestPath = requestPath(pkg, requestFacts);
        String resourceId = resourceId(pkg, requestFacts, promptMetadata);
        String actualTargetResourceId = actualResourceId(requestFacts, promptMetadata, requestPath, resourceId, pkg);
        String method = httpMethod(requestFacts);
        boolean integrityValid = lookupService.verifyIntegrity(pkg);
        RuntimeEvidencePromptConsistencyResult promptConsistency = promptConsistencyGate.evaluate(pkg);
        String operatorId = firstNonBlank(request.operatorId(), pkg.getUserId(), "runtime-pqa");
        PromptQualityProcessScope processScope = new PromptQualityProcessScope(
                firstNonBlank(pkg.getTenantId(), PromptQualityAssuranceScope.DEFAULT_TENANT_ID),
                requestPath,
                resourceId,
                method,
                PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION,
                PromptQualityAssuranceScope.DEFAULT_MODEL_PROFILE,
                PromptQualityAssuranceScope.DEFAULT_VERIFIER_VERSION);
        OfficialVerificationExecutionLockService.ExecutionRecord executionRecord = null;
        ProtectableResourceDescriptor descriptor = null;
        try {
            descriptor = resourceLookup
                    .findBestMatch(requestPath, resourceId, method)
                    .orElse(null);
            executionRecord = executionLockService.start(executionRequest(
                    request,
                    pkg,
                    requestFacts,
                    promptMetadata,
                    descriptor,
                    requestPath,
                    resourceId,
                    method,
                    operatorId));
            completeOfficialVerificationPrerequisites(processScope, pkg, integrityValid, promptConsistency, operatorId);
            if (!executionRecord.acquired()) {
                return idempotentExecutionRun(
                        executionRecord,
                        pkg,
                        requestFacts,
                        promptMetadata,
                        requestPath,
                        resourceId,
                        method,
                        promptConsistency);
            }
            replacePreviousDiagnosticsForQualityTarget(
                    pkg.getPackageId(),
                    actualTargetResourceId,
                    requestPath,
                    method);
            executionLockService.transition(
                    executionRecord,
                    OfficialVerificationExecutionLockService.STATE_EVIDENCE_LOADED,
                    OfficialVerificationProgressPolicy.EVIDENCE_LOADED,
                    "Selected sealed runtime evidence was loaded for official verification.");
            assertOfficialVerificationProcessReady(processScope);
            executionLockService.transition(
                    executionRecord,
                    OfficialVerificationExecutionLockService.STATE_CONSISTENCY_CHECKED,
                    OfficialVerificationProgressPolicy.CONSISTENCY_CHECKED,
                    "Evidence and prompt consistency prerequisites were checked.");
            if (promptConsistency != null && promptConsistency.blocking()) {
                startOfficialVerificationStep(processScope, pkg, operatorId);
            }
            assertPromptConsistencyReady(promptConsistency);
            startOfficialVerificationStep(processScope, pkg, operatorId);
            ScorecardResult scorecard = safeScorecard(pkg);
            DeterministicReplayResult replay = safeReplay(pkg);
            executionLockService.transition(
                    executionRecord,
                    OfficialVerificationExecutionLockService.STATE_PREFLIGHT_FINAL_PROMPT_CONTRACT,
                    OfficialVerificationProgressPolicy.FINAL_PROMPT_PREFLIGHT,
                    "Final prompt storage contract is being checked before the 12 metrics run.");
            assertSealedPromptEvidencePackage(pkg);
            finalPromptPreflightService.assertReady(pkg);
            String failureAggregateRunId = failureAggregateRunId(pkg, executionRecord);
            executionLockService.markMetricsRunning(executionRecord, failureAggregateRunId, expectedMetricCodes());
            OfficialSealedEvidenceVerificationResult officialResult = officialSealedEvidenceVerificationRuntime.executeAll(
                    new OfficialSealedEvidenceVerificationRequest(pkg.getPackageId(), operatorId));
            List<? extends OfficialVerificationRunView> runViews = officialResult.runs();
            assertOfficialMetricRunsComplete(runViews);
            recordMetricFinished(executionRecord, officialResult.aggregateRunId(), runViews);
            executionLockService.transition(
                    executionRecord,
                    OfficialVerificationExecutionLockService.STATE_SNAPSHOT_WRITING,
                    OfficialVerificationProgressPolicy.SNAPSHOT_WRITING,
                    "Official metric results were produced; the latest operator diagnostic snapshot is being stored.");
        certificationPolicy.evaluate(pkg, integrityValid, scorecard, replay, runViews);
        OfficialContextHashStateResolver.Resolution contextHashResolution =
                OfficialContextHashStateResolver.resolve(requestFacts, promptMetadata, pkg.getCanonicalContextJson());
        String resolvedContextHash = contextHashResolution.contextHash();
        String requestId = firstNonBlank(
                text(requestFacts, "requestId"),
                text(promptMetadata, "requestId"),
                pkg.getCorrelationId());
        String promptHash = firstNonBlank(pkg.getPromptHash(), text(promptMetadata, "promptHash"));
        String contextHash = resolvedContextHash;

        List<OfficialVerificationPromptComparison> promptComparisons = executionComparisons(
                pkg,
                requestId,
                requestPath,
                resourceId,
                promptHash,
                resolvedContextHash,
                requestFacts,
                authState,
                promptMetadata,
                decision,
                runViews);
        List<RuntimeEvidenceMetricResult> metrics = toMetricResults(
                runViews,
                promptComparisons,
                pkg.getPackageId(),
                officialResult.aggregateRunId());

        List<MetricRunEvidence> evidence = metrics.stream()
                .map(metric -> new MetricRunEvidence(metric.metricCode(), runtimeMetricRunView(metric, requestId)))
                .toList();
        int officialFailed = (int) metrics.stream().filter(this::customerBlockingMetric).count();
        List<MetricExecutionFailure> failures = promptConsistency.passed()
                ? List.of()
                : List.of(new MetricExecutionFailure(
                        "PFR",
                        message(
                                "enterprise.pqa.promptConsistency.certificate.blocked",
                                "The sealed evidence does not reliably represent the final LLM prompt.")));
        PromptQualityCertificateService.CertificateScope scope = PromptQualityCertificateService.CertificateScope.of(
                firstNonBlank(pkg.getTenantId(), PromptQualityAssuranceScope.DEFAULT_TENANT_ID),
                requestPath,
                method,
                resourceId,
                PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION,
                PromptQualityAssuranceScope.DEFAULT_MODEL_PROFILE,
                PromptQualityAssuranceScope.DEFAULT_VERIFIER_VERSION);
        PromptQualityCertificate certificate = certificateIssuer.issue(
                generatedAt,
                operatorId,
                scope,
                descriptor,
                evidence,
                failures);

        PromptQualityAssuranceScope assuranceScope = new PromptQualityAssuranceScope(
                scope.tenantId(),
                scope.resourceUrl(),
                scope.protectableResourceId(),
                scope.httpMethod(),
                scope.promptContractVersion(),
                scope.modelProfile(),
                scope.verifierVersion());
        int failed = officialFailed + (promptConsistency.passed() ? 0 : 1);
        String runId = officialResult.aggregateRunId();
        PromptQualityAssuranceCase verifiedCase = assuranceCaseService.recordVerification(
                assuranceScope,
                runId,
                failed,
                message(
                        "enterprise.pqa.runtimeVerification.case.summaryTpl",
                        "Official verification for real request evidence {0}",
                        pkg.getPackageId()));
        PromptQualityAssuranceCase certifiedCase = assuranceCaseService.recordCertificate(
                assuranceScope,
                certificate.certificateId(),
                failed,
                certificate.summary());
        PromptQualityAssuranceCase finalCase = certifiedCase == null ? verifiedCase : certifiedCase;
        List<String> rawFindings = merge(certificate.blockingFindings(), promptConsistency.findings());
        List<String> findings = customerVisibleRuntimeSentences(rawFindings, true);
        List<String> rawNextActions = certificate.usableForLlmZeroTrust()
                ? List.of(message(
                "enterprise.pqa.runtimeVerification.next.certificateIssued",
                "Prompt quality certificate was issued. Continue operational promotion from the promotion screen."))
                : merge(certificate.recommendedActions(), promptConsistency.nextActions());
        List<String> nextActions = customerVisibleRuntimeSentences(rawNextActions, false);
        List<PromptQualityIssue> issues = runtimeIssueDiagnosticService.recordIssues(
                runId,
                pkg.getPackageId(),
                method,
                issueMetrics(metrics, promptConsistency),
                nextActions);
        List<OfficialRunFailureCause> failureCauses = failureCauses(metrics);
        recordOperatorSnapshot(
                runId,
                pkg,
                requestPath,
                actualTargetResourceId,
                method,
                promptHash,
                resolvedContextHash,
                certificate.certificateId(),
                finalCase == null ? null : finalCase.caseId(),
                issues,
                metrics,
                promptComparisons);
        List<OfficialActualPromptProblem> actualPromptProblems = List.of();
        if (operatorSnapshotService != null) {
            List<OfficialVerificationPromptComparison> storedPromptComparisons =
                    operatorSnapshotService.promptComparisons(pkg.getPackageId(), runId);
            if (!storedPromptComparisons.isEmpty()) {
                promptComparisons = storedPromptComparisons;
            }
            actualPromptProblems = operatorSnapshotService.actualPromptProblems(pkg.getPackageId(), runId);
        }
        List<String> officialFindings = actualPromptProblemFindings(actualPromptProblems);
        List<String> officialNextActions = actualPromptProblemNextActions(actualPromptProblems);
        if (officialNextActions.isEmpty()) {
            officialNextActions = certificate.usableForLlmZeroTrust()
                    ? List.of(message(
                    "enterprise.pqa.runtimeVerification.next.certificateIssued",
                    "Prompt quality certificate was issued. Continue operational promotion from the promotion screen."))
                    : List.of();
        }
        int officialPromptFailed = actualPromptProblemMetricCount(actualPromptProblems);
        int officialPromptPassed = Math.max(metrics.size() - officialPromptFailed, 0);
        recordVerificationProcess(processScope, certificate, pkg, runId, officialPromptFailed, officialNextActions);
        recordOfficialAuditSnapshot(
                processScope,
                certificate,
                finalCase,
                pkg,
                runId,
                metrics,
                officialPromptFailed,
                officialFindings,
                officialNextActions,
                requestId,
                promptHash,
                contextHash,
                promptMetadata,
                operatorId);

        RuntimeEvidenceVerificationRun run = new RuntimeEvidenceVerificationRun(
                runId,
                pkg.getPackageId(),
                generatedAt,
                finalCase == null ? null : finalCase.caseId(),
                certificate.certificateId(),
                certificate.state(),
                certificate.stateLabel(),
                certificate.usableForLlmZeroTrust(),
                certificate.summary(),
                certificate.summary(),
                metrics.size(),
                officialPromptPassed,
                officialPromptFailed,
                pkg.getTenantId(),
                pkg.getUserId(),
                requestPath,
                resourceId,
                method,
                metrics,
                issues,
                officialFindings,
                officialNextActions,
                requestId,
                promptHash,
                contextHash,
                failureCauses,
                promptComparisons,
                actualPromptProblems,
                promptConsistency);
        executionLockService.markCompleted(executionRecord, runId, run);
        return run;
        }
        catch (RuntimeException ex) {
            log.error(
                    "PQA official verification failed. packageId={}, requestPath={}, resourceId={}, httpMethod={}, executionRecordPresent={}, executionState={}",
                    pkg.getPackageId(),
                    requestPath,
                    resourceId,
                    method,
                    executionRecord != null,
                    executionRecord == null ? null : executionRecord.state(),
                    ex);
            if (executionRecord == null) {
                executionRecord = startFailureRecord(
                        request,
                        pkg,
                        requestFacts,
                        promptMetadata,
                        requestPath,
                        resourceId,
                        method,
                        operatorId);
            }
            boolean recoverable = recoverableOfficialVerificationFailure(ex);
            try {
                executionLockService.markFailed(
                        executionRecord,
                        ex,
                        recoverable,
                        officialVerificationRetryInstruction(recoverable));
            }
            catch (RuntimeException ledgerFailure) {
                log.error(
                        "PQA official verification failure ledger write failed. packageId={}, requestPath={}, resourceId={}, httpMethod={}, executionRecordPresent={}",
                        pkg.getPackageId(),
                        requestPath,
                        resourceId,
                        method,
                        executionRecord != null,
                        ledgerFailure);
            }
            try {
                processRunService.failStep(
                        processScope,
                        PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                        PromptQualityStateDimension.CERTIFICATE.name(),
                        "FAILED",
                        pkg.getPackageId(),
                        verificationReadinessRoute(pkg.getPackageId(), processScope, null),
                        ex.getMessage(),
                        operatorId,
                        "Official verification failed before a complete result could be stored.");
            }
            catch (RuntimeException processFailure) {
                log.error(
                        "PQA official verification process failure write failed. packageId={}, requestPath={}, resourceId={}, httpMethod={}",
                        pkg.getPackageId(),
                        requestPath,
                        resourceId,
                        method,
                        processFailure);
            }
            throw ex;
        }
    }

    private void replacePreviousDiagnosticsForQualityTarget(
            String packageId,
            String resourceId,
            String requestPath,
            String method) {
        if (operatorSnapshotService == null) {
            return;
        }
        List<String> replacedPackageIds = operatorSnapshotService.replaceDiagnosticsForQualityTarget(
                packageId,
                resourceId,
                requestPath,
                method);
        executionLockService.deleteFinishedExecutionsForPackages(replacedPackageIds);
    }

    private SealedEvidencePackage prepareSealedPromptEvidencePackage(SealedEvidencePackage loadedPackage) {
        SealedEvidencePromptEvidenceBackfill.Result result =
                SealedEvidencePromptEvidenceBackfill.prepare(objectMapper, loadedPackage);
        if (result.recovered()) {
            log.warn(
                    "PQA sealed evidence prompt contract recovered for official verification. packageId={}, recoveredFields={}",
                    loadedPackage == null ? null : loadedPackage.getPackageId(),
                    result.recoveredFields());
        }
        if (!result.ready()) {
            throw new IllegalStateException("The sealed evidence package does not satisfy the official inspection input contract. "
                    + String.join(" ", result.violations())
                    + " Existing evidence cannot be used for official inspection when the actual prompt text or required sealed proof is missing. Request the same protected resource again and create a new sealed evidence package.");
        }
        return result.packageForVerification();
    }

    private void assertSealedPromptEvidencePackage(SealedEvidencePackage pkg) {
        List<String> violations = new ArrayList<>();
        if (!"SEALED".equalsIgnoreCase(firstNonBlank(pkg.getSealState(), ""))) {
            violations.add("sealState is not SEALED.");
        }
        if (!StringUtils.hasText(pkg.getPromptEvidenceManifestJson())) {
            violations.add("The actual prompt evidence manifest is missing.");
        }
        if (!StringUtils.hasText(pkg.getSystemPromptHash())) {
            violations.add("systemPromptHash is missing.");
        }
        if (!StringUtils.hasText(pkg.getUserPromptHash())) {
            violations.add("userPromptHash is missing.");
        }
        if (!StringUtils.hasText(pkg.getRawSystemPromptHash())) {
            violations.add("rawSystemPromptHash is missing.");
        }
        if (!StringUtils.hasText(pkg.getRawUserPromptHash())) {
            violations.add("rawUserPromptHash is missing.");
        }
        Map<String, Object> manifest = parseJson(pkg.getPromptEvidenceManifestJson());
        Object sealable = manifest.get("sealable");
        if (!manifest.isEmpty() && !Boolean.TRUE.equals(sealable)) {
            log.warn(
                    "PQA sealed evidence prompt projection contract failed; official verification will continue and record the failed fields as findings. packageId={}, sealFailureReason={}",
                    pkg.getPackageId(),
                    pkg.getSealFailureReason());
        }
        if (!violations.isEmpty()) {
            throw new IllegalStateException("The sealed evidence package does not satisfy the official inspection input contract. "
                    + String.join(" ", violations));
        }
    }

    @Override
    public OfficialVerificationExecutionStatus executionStatus(String packageId) {
        return executionLockService.status(packageId);
    }

    @Override
    public RuntimeEvidenceReverifyResult reverify(RuntimeEvidenceReverifyRequest request) {
        String operatorId = firstNonBlank(request == null ? null : request.operatorId(), "runtime-pqa");
        RuntimeEvidenceVerificationRun run = verify(new RuntimeEvidenceVerificationRequest(
                request == null ? null : request.packageId(),
                operatorId,
                true,
                firstNonBlank(
                        request == null ? null : request.reason(),
                        "Reverification requested after remediation.")));
        List<RuntimeEvidenceReverifyFindingResult> findingResults = operatorSnapshotService == null || request == null
                ? List.of()
                : operatorSnapshotService.recordReverificationResults(
                        request.sourcePackageId(),
                        request.sourceAggregateRunId(),
                        request.findingIds(),
                        request.issueIds(),
                        run,
                        operatorId);
        boolean linkedCriteriaSatisfied = !findingResults.isEmpty()
                && findingResults.stream().allMatch(RuntimeEvidenceReverifyFindingResult::resolved);
        PromptQualityProcessScope scope = new PromptQualityProcessScope(
                firstNonBlank(run.tenantId(), PromptQualityAssuranceScope.DEFAULT_TENANT_ID),
                run.resourceUrl(),
                run.resourceId(),
                run.httpMethod(),
                PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION,
                PromptQualityAssuranceScope.DEFAULT_MODEL_PROFILE,
                PromptQualityAssuranceScope.DEFAULT_VERIFIER_VERSION);
        processRunService.completeStep(
                scope,
                PromptQualityProcessCodes.REVERIFICATION,
                PromptQualityStateDimension.CERTIFICATE.name(),
                run.certificateState(),
                run.packageId(),
                verificationReadinessRoute(run.packageId(), scope, run.aggregateRunId()),
                run.certificateSummary(),
                run.nextActions().stream().findFirst().orElse(""),
                Map.of(
                        "certificateIssued", run.certificateIssued(),
                        "linkedFindingCount", findingResults.size(),
                        "linkedCriteriaSatisfied", linkedCriteriaSatisfied),
                operatorId,
                "Reverification completed from sealed runtime evidence.");
        String instruction = reverifyInstruction(run, findingResults, linkedCriteriaSatisfied);
        return new RuntimeEvidenceReverifyResult(
                run.packageId(),
                run,
                instruction,
                request == null ? null : request.sourcePackageId(),
                request == null ? null : request.sourceAggregateRunId(),
                linkedCriteriaSatisfied,
                findingResults);
    }

    private String reverifyInstruction(
            RuntimeEvidenceVerificationRun run,
            List<RuntimeEvidenceReverifyFindingResult> findingResults,
            boolean linkedCriteriaSatisfied) {
        if (findingResults != null && !findingResults.isEmpty()) {
            long unresolved = findingResults.stream().filter(result -> !result.resolved()).count();
            if (linkedCriteriaSatisfied && run.certificateIssued()) {
                return message(
                        "enterprise.pqa.runtimeVerification.reverify.linkedPassed",
                        "The new request evidence passed official inspection, and all previous remediation criteria were satisfied. Continue to operational promotion.");
            }
            if (unresolved > 0) {
                return message(
                        "enterprise.pqa.runtimeVerification.reverify.unresolvedTpl",
                        "{0} previous remediation criteria are still unresolved. Fix the remaining items, request the protected resource again, and reverify with the new evidence packageId.",
                        unresolved);
            }
            return message(
                    "enterprise.pqa.runtimeVerification.reverify.criteriaPassedCertificateBlocked",
                    "Previous remediation criteria were satisfied, but certificate issuance is still blocked. Check the failed official metric details.");
        }
        return run.certificateIssued()
                ? message(
                "enterprise.pqa.runtimeVerification.reverify.passed",
                "The new request evidence passed. Move to operational promotion.")
                : message(
                "enterprise.pqa.runtimeVerification.reverify.blocked",
                "Call the protected resource again after remediation, then reverify with the new request evidence packageId.");
    }

    private void startOfficialVerificationStep(
            PromptQualityProcessScope processScope,
            SealedEvidencePackage pkg,
            String operatorId) {
        processRunService.startStep(
                processScope,
                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                PromptQualityStateDimension.PROCESS_STAGE.name(),
                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                pkg.getPackageId(),
                verificationReadinessRoute(pkg.getPackageId(), processScope, null),
                operatorId,
                "Official verification started from sealed runtime evidence.");
    }

    private OfficialVerificationExecutionLockService.ExecutionRequest executionRequest(
            RuntimeEvidenceVerificationRequest request,
            SealedEvidencePackage pkg,
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            ProtectableResourceDescriptor descriptor,
            String requestPath,
            String resourceId,
            String method,
            String operatorId) {
        Map<String, String> components = new LinkedHashMap<>();
        components.put("packageId", safe(pkg == null ? null : pkg.getPackageId()));
        components.put("sealedEvidenceHash", safe(pkg == null ? null : pkg.getPackageHash()));
        components.put("promptHash", safe(firstNonBlank(pkg == null ? null : pkg.getPromptHash(), text(promptMetadata, "promptHash"))));
        components.put("promptGovernanceVersion", safe(promptGovernanceVersion(promptMetadata)));
        components.put("metricSetVersion", metricSetVersion());
        components.put("officialVerificationEngineVersion", officialVerificationEngineVersion());
        components.put("actualPromptProblemLedgerContractVersion",
                OfficialVerificationOperatorSnapshotService.ACTUAL_PROMPT_PROBLEM_LEDGER_CONTRACT_VERSION);
        components.put("resourceTemplateId", safe(resourceTemplateId(requestFacts, promptMetadata, descriptor, resourceId)));
        components.put("actualResourceId", safe(actualResourceId(requestFacts, promptMetadata, requestPath, resourceId, pkg)));
        components.put("httpMethod", safe(method));
        String fingerprintJson = writeJson(components);
        String key = "pqa-official:" + sha256Hex(fingerprintJson);
        return new OfficialVerificationExecutionLockService.ExecutionRequest(
                key,
                key,
                pkg.getPackageId(),
                operatorId,
                request != null && request.forceReverification(),
                request == null ? null : request.reverificationReason(),
                fingerprintJson);
    }

    private OfficialVerificationExecutionLockService.ExecutionRecord startFailureRecord(
            RuntimeEvidenceVerificationRequest request,
            SealedEvidencePackage pkg,
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            String requestPath,
            String resourceId,
            String method,
            String operatorId) {
        try {
            OfficialVerificationExecutionLockService.ExecutionRecord record = executionLockService.start(executionRequest(
                    request,
                    pkg,
                    requestFacts,
                    promptMetadata,
                    null,
                    requestPath,
                    resourceId,
                    method,
                    operatorId));
            return record.acquired() ? record : null;
        }
        catch (RuntimeException ignored) {
            log.error(
                    "PQA official verification pre-ledger failure record could not be created. packageId={}, requestPath={}, resourceId={}, httpMethod={}",
                    pkg == null ? null : pkg.getPackageId(),
                    requestPath,
                    resourceId,
                    method,
                    ignored);
            return null;
        }
    }

    private RuntimeEvidenceVerificationRun idempotentExecutionRun(
            OfficialVerificationExecutionLockService.ExecutionRecord record,
            SealedEvidencePackage pkg,
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            String requestPath,
            String resourceId,
            String method,
            RuntimeEvidencePromptConsistencyResult promptConsistency) {
        if (record.completed()) {
            return executionLockService.completedResult(record)
                    .orElseGet(() -> executionStatusRun(
                            record,
                            pkg,
                            requestFacts,
                            promptMetadata,
                            requestPath,
                            resourceId,
                            method,
                            promptConsistency,
                            "The latest official verification diagnostic result is missing.",
                            "Run the inspection again. The new diagnostic result will replace the previous one."));
        }
        if (record.failed()) {
            return executionStatusRun(
                    record,
                    pkg,
                    requestFacts,
                    promptMetadata,
                    requestPath,
                    resourceId,
                    method,
                    promptConsistency,
                    firstNonBlank(record.failureReason(), "The previous official verification attempt failed."),
                    firstNonBlank(record.retryInstruction(), "Fix the failure reason, then run the inspection again."));
        }
        return executionStatusRun(
                record,
                pkg,
                requestFacts,
                promptMetadata,
                requestPath,
                resourceId,
                method,
                promptConsistency,
                "Official verification is already running for this sealed evidence.",
                "Wait for the existing execution to finish. The latest result will replace the previous diagnostic data.");
    }

    private RuntimeEvidenceVerificationRun executionStatusRun(
            OfficialVerificationExecutionLockService.ExecutionRecord record,
            SealedEvidencePackage pkg,
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            String requestPath,
            String resourceId,
            String method,
            RuntimeEvidencePromptConsistencyResult promptConsistency,
            String summary,
            String nextAction) {
        String state = firstNonBlank(record.state(), "RUNNING");
        String runId = firstNonBlank(record.aggregateRunId(), "pending-" + record.idempotencyKey().substring(0, Math.min(record.idempotencyKey().length(), 24)));
        String requestId = firstNonBlank(
                text(requestFacts, "requestId"),
                text(promptMetadata, "requestId"),
                pkg == null ? null : pkg.getCorrelationId());
        String promptHash = firstNonBlank(pkg == null ? null : pkg.getPromptHash(), text(promptMetadata, "promptHash"));
        String contextHash = OfficialContextHashStateResolver.resolve(
                requestFacts,
                promptMetadata,
                pkg == null ? null : pkg.getCanonicalContextJson()).contextHash();
        return new RuntimeEvidenceVerificationRun(
                runId,
                pkg == null ? record.packageId() : pkg.getPackageId(),
                now(),
                null,
                null,
                state,
                executionStateLabel(state),
                false,
                summary,
                summary,
                metricCatalog.promptQualityMetrics().size(),
                0,
                0,
                pkg == null ? null : pkg.getTenantId(),
                pkg == null ? null : pkg.getUserId(),
                requestPath,
                resourceId,
                method,
                List.of(),
                List.of(),
                record.failed() ? List.of(summary) : List.of(),
                List.of(nextAction),
                requestId,
                promptHash,
                contextHash,
                List.of(),
                List.of(),
                List.of(),
                promptConsistency,
                state,
                record.progressPercent());
    }

    private String executionStateLabel(String state) {
        return switch (safe(state).toUpperCase(Locale.ROOT)) {
            case OfficialVerificationExecutionLockService.STATE_LOCK_ACQUIRED -> "Official inspection lock acquired";
            case OfficialVerificationExecutionLockService.STATE_EVIDENCE_LOADED -> "Official inspection evidence loaded";
            case OfficialVerificationExecutionLockService.STATE_CONSISTENCY_CHECKED -> "Official inspection prerequisite checked";
            case OfficialVerificationExecutionLockService.STATE_PREFLIGHT_FINAL_PROMPT_CONTRACT -> "Final prompt storage contract is being checked";
            case OfficialVerificationExecutionLockService.STATE_METRICS_RUNNING -> "Official inspection metrics running";
            case OfficialVerificationExecutionLockService.STATE_SNAPSHOT_WRITING -> "Official inspection result is being stored";
            case OfficialVerificationExecutionLockService.STATE_COMPLETED -> "Official inspection completed";
            case OfficialVerificationExecutionLockService.STATE_OFFICIAL_VERIFICATION_PREFLIGHT_FAILED -> "Official inspection preflight failed";
            case OfficialVerificationExecutionLockService.STATE_FAILED_RECOVERABLE -> "Official inspection failed; retry is available";
            case OfficialVerificationExecutionLockService.STATE_FAILED_TERMINAL -> "Official inspection failed; new evidence or remediation is required";
            default -> "Official inspection status";
        };
    }

    private String promptGovernanceVersion(Map<String, Object> promptMetadata) {
        Map<String, Object> governance = mapValue(promptMetadata, "governanceDescriptor");
        return firstNonBlank(
                text(promptMetadata, "promptVersion"),
                text(governance, "promptVersion"),
                text(governance, "contractVersion"));
    }

    private String resourceTemplateId(
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            ProtectableResourceDescriptor descriptor,
            String resourceId) {
        return firstNonBlank(
                text(requestFacts, "protectableResourceId"),
                text(promptMetadata, "protectableResourceId"),
                descriptor == null ? null : descriptor.resourceId(),
                containsTemplateMarker(resourceId) ? resourceId : null,
                resourceId);
    }

    private String actualResourceId(
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            String requestPath,
            String resourceId,
            SealedEvidencePackage pkg) {
        return firstNonBlank(
                text(requestFacts, "actualResourceId"),
                text(promptMetadata, "actualResourceId"),
                containsTemplateMarker(text(requestFacts, "resourceId")) ? null : text(requestFacts, "resourceId"),
                containsTemplateMarker(text(requestFacts, "endpointKey")) ? null : text(requestFacts, "endpointKey"),
                containsTemplateMarker(text(promptMetadata, "resourceId")) ? null : text(promptMetadata, "resourceId"),
                containsTemplateMarker(resourceId) ? null : resourceId,
                lastPathSegment(requestPath),
                pkg == null ? null : pkg.getPackageId());
    }

    private boolean containsTemplateMarker(String value) {
        return StringUtils.hasText(value) && value.contains("{") && value.contains("}");
    }

    private String lastPathSegment(String requestPath) {
        if (!StringUtils.hasText(requestPath) || containsTemplateMarker(requestPath)) {
            return null;
        }
        String normalized = requestPath.trim();
        int queryIndex = normalized.indexOf('?');
        if (queryIndex >= 0) {
            normalized = normalized.substring(0, queryIndex);
        }
        String[] parts = normalized.split("/");
        for (int i = parts.length - 1; i >= 0; i--) {
            if (StringUtils.hasText(parts[i])) {
                return parts[i].trim();
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> mapValue(Map<String, Object> source, String key) {
        if (source == null || !source.containsKey(key) || !(source.get(key) instanceof Map<?, ?> raw)) {
            return Map.of();
        }
        Map<String, Object> result = new LinkedHashMap<>();
        raw.forEach((nestedKey, value) -> {
            if (nestedKey != null) {
                result.put(String.valueOf(nestedKey), value);
            }
        });
        return result;
    }

    private String metricSetVersion() {
        String material = metricCatalog.promptQualityMetrics().stream()
                .map(metric -> safe(metric.code()) + ":" + safe(metric.metricName()) + ":" + safe(metric.category())
                        + ":" + metric.benchmarkSuccessThreshold() + ":" + metric.official())
                .collect(Collectors.joining("|"));
        return "PQA12-" + sha256Hex(material).substring(0, 16);
    }

    private String officialVerificationEngineVersion() {
        String implementationVersion = officialSealedEvidenceVerificationRuntime.getClass().getPackage() == null
                ? null
                : officialSealedEvidenceVerificationRuntime.getClass().getPackage().getImplementationVersion();
        return firstNonBlank(implementationVersion, officialSealedEvidenceVerificationRuntime.getClass().getName());
    }

    private List<String> expectedMetricCodes() {
        return metricCatalog.promptQualityMetrics().stream()
                .map(OfficialVerificationMetricDefinition::code)
                .filter(StringUtils::hasText)
                .map(code -> code.trim().toUpperCase(Locale.ROOT))
                .distinct()
                .toList();
    }

    private String failureAggregateRunId(
            SealedEvidencePackage pkg,
            OfficialVerificationExecutionLockService.ExecutionRecord executionRecord) {
        return "osev-failed-" + safe(pkg == null ? null : pkg.getPackageId())
                + "-lock-" + (executionRecord == null ? "unknown" : executionRecord.id())
                + "-attempt-" + (executionRecord == null ? 1 : executionRecord.attemptNo());
    }

    private void recordMetricFinished(
            OfficialVerificationExecutionLockService.ExecutionRecord executionRecord,
            String aggregateRunId,
            List<? extends OfficialVerificationRunView> runViews) {
        if (executionRecord == null || runViews == null || runViews.isEmpty()) {
            return;
        }
        int total = Math.max(runViews.size(), 1);
        for (int i = 0; i < runViews.size(); i++) {
            OfficialVerificationRunView run = runViews.get(i);
            String metricCode = run == null ? null : run.endpointKey();
            int progress = OfficialVerificationProgressPolicy.metricProgress(i + 1, total);
            executionLockService.markMetricCompleted(executionRecord, aggregateRunId, metricCode, progress);
        }
    }

    private void assertOfficialMetricRunsComplete(List<? extends OfficialVerificationRunView> runViews) {
        Set<String> expected = new LinkedHashSet<>(expectedMetricCodes());
        Set<String> actual = runViews == null
                ? Set.of()
                : runViews.stream()
                .filter(run -> run != null && StringUtils.hasText(run.endpointKey()))
                .map(run -> run.endpointKey().trim().toUpperCase(Locale.ROOT))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        List<String> missing = expected.stream()
                .filter(metricCode -> !actual.contains(metricCode))
                .toList();
        if (!missing.isEmpty()) {
            throw new IllegalStateException("Official metric runtime did not produce all configured prompt quality metrics. missingMetricCodes="
                    + String.join(",", missing));
        }
    }

    private boolean recoverableOfficialVerificationFailure(RuntimeException exception) {
        if (exception == null) {
            return true;
        }
        String message = exception.getMessage() == null ? "" : exception.getMessage();
        if (message.contains("does not reliably represent the final LLM prompt")
                || message.contains("sealed evidence does not reliably represent")
                || message.contains("final LLM prompt")) {
            return false;
        }
        return true;
    }

    private String officialVerificationRetryInstruction(boolean recoverable) {
        return recoverable
                ? message(
                "enterprise.pqa.runtimeVerification.retry.recoverable",
                "Fix the failed stage cause, then run the same evidence package again. The new result will replace the previous diagnostic data.")
                : message(
                "enterprise.pqa.runtimeVerification.retry.terminal",
                "Do not retry this evidence package unchanged. Request the protected resource again to collect new sealed evidence, or resolve the cause in remediation first.");
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value == null ? Map.of() : value);
        }
        catch (Exception exception) {
            throw new IllegalStateException("Official verification idempotency fingerprint cannot be serialized.", exception);
        }
    }

    private String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest((value == null ? "" : value).getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available.", exception);
        }
    }

    private String safe(String value) {
        return StringUtils.hasText(value) ? value.trim() : "";
    }

    private void recordVerificationProcess(
            PromptQualityProcessScope processScope,
            PromptQualityCertificate certificate,
            SealedEvidencePackage pkg,
            String runId,
            int failed,
            List<String> nextActions) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("aggregateRunId", runId);
        result.put("certificateId", certificate.certificateId());
        result.put("certificateState", certificate.state());
        result.put("failedMetricCount", failed);
        result.put("usableForLlmZeroTrust", certificate.usableForLlmZeroTrust());
        processRunService.completeStep(
                processScope,
                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                PromptQualityStateDimension.CERTIFICATE.name(),
                certificate.state(),
                runId,
                verificationReadinessRoute(pkg.getPackageId(), processScope, runId),
                certificate.summary(),
                nextActions.stream().findFirst().orElse(""),
                result,
                "runtime-pqa",
                "Official verification completed.");
        if (certificate.usableForLlmZeroTrust()) {
            processRunService.startStep(
                    processScope,
                    PromptQualityProcessCodes.CERTIFICATES_PROMOTION,
                    PromptQualityStateDimension.CERTIFICATE.name(),
                    certificate.state(),
                    certificate.certificateId(),
                    verificationMetricsRoute(pkg.getPackageId(), processScope, runId),
                    "runtime-pqa",
                    "Quality certificate issued; operational promotion is now waiting.");
        }
        else {
            processRunService.startStep(
                    processScope,
                    PromptQualityProcessCodes.REMEDIATION,
                    PromptQualityStateDimension.CERTIFICATE.name(),
                    certificate.state(),
                    certificate.certificateId(),
                    verificationMetricsRoute(pkg.getPackageId(), processScope, runId),
                    "runtime-pqa",
                    "Official verification produced blocking findings.");
        }
    }

    private void recordOfficialAuditSnapshot(
            PromptQualityProcessScope processScope,
            PromptQualityCertificate certificate,
            PromptQualityAssuranceCase assuranceCase,
            SealedEvidencePackage pkg,
            String runId,
            List<RuntimeEvidenceMetricResult> metrics,
            int failedMetricCount,
            List<String> findings,
            List<String> nextActions,
            String requestId,
            String promptHash,
            String contextHash,
            Map<String, Object> promptMetadata,
            String operatorId) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("packageId", pkg.getPackageId());
        payload.put("aggregateRunId", runId);
        payload.put("requestId", requestId);
        payload.put("tenantId", pkg.getTenantId());
        payload.put("userId", pkg.getUserId());
        payload.put("resourceUrl", processScope.resourceUrl());
        payload.put("resourceId", processScope.resourceId());
        payload.put("httpMethod", processScope.httpMethod());
        payload.put("certificateId", certificate.certificateId());
        payload.put("certificateState", certificate.state());
        payload.put("certificateIssued", certificate.usableForLlmZeroTrust());
        payload.put("caseId", assuranceCase == null ? null : assuranceCase.caseId());
        payload.put("totalMetricCount", metrics == null ? 0 : metrics.size());
        payload.put("failedMetricCount", failedMetricCount);
        payload.put("failedMetricCodes", metrics == null
                ? List.of()
                : metrics.stream().filter(this::customerBlockingMetric).map(RuntimeEvidenceMetricResult::metricCode).toList());
        payload.put("promptHash", promptHash);
        payload.put("contextHash", contextHash);
        payload.put("promptGovernanceVersion", promptGovernanceVersion(promptMetadata));
        payload.put("metricSetVersion", metricSetVersion());
        payload.put("officialVerificationEngineVersion", officialVerificationEngineVersion());
        payload.put("blockingFindings", findings == null ? List.of() : findings);
        payload.put("nextActions", nextActions == null ? List.of() : nextActions);
        if (operatorSnapshotService != null) {
            operatorSnapshotService.recordAuditSnapshot(
                    runId,
                    pkg.getPackageId(),
                    certificate.certificateId(),
                    assuranceCase == null ? null : assuranceCase.caseId(),
                    certificate.state(),
                    certificate.stateLabel(),
                    metrics == null ? 0 : metrics.size(),
                    failedMetricCount,
                    certificate.usableForLlmZeroTrust(),
                    promptHash,
                    contextHash,
                    findings == null ? List.of() : findings,
                    nextActions == null ? List.of() : nextActions,
                    payload,
                    firstNonBlank(operatorId, "runtime-pqa"));
        }
        processRunService.recordEvent(
                processScope,
                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                "OFFICIAL_VERIFICATION_AUDIT_SNAPSHOT",
                payload,
                firstNonBlank(operatorId, "runtime-pqa"),
                "Official verification audit snapshot persisted.");
    }

    private void completeOfficialVerificationPrerequisites(
            PromptQualityProcessScope processScope,
            SealedEvidencePackage pkg,
            boolean integrityValid,
            RuntimeEvidencePromptConsistencyResult promptConsistency,
            String operatorId) {
        List<PromptQualityProcessStepSnapshot> steps = processRunService.steps(processScope);
        if (shouldCompletePrerequisite(steps, PromptQualityProcessCodes.PROTECTABLE_RESOURCES)) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("packageId", pkg.getPackageId());
            result.put("resourceId", processScope.resourceId());
            result.put("resourceUrl", processScope.resourceUrl());
            result.put("httpMethod", processScope.httpMethod());
            processRunService.completeStep(
                    processScope,
                    PromptQualityProcessCodes.PROTECTABLE_RESOURCES,
                    PromptQualityStateDimension.RESOURCE_OPERATIONAL.name(),
                    "PENDING_VERIFICATION",
                    processScope.resourceId(),
                    resourceDetailRoute(processScope),
                    message(
                            "enterprise.pqa.runtimeVerification.process.resourceResolved",
                            "Protected resource was resolved from sealed runtime evidence."),
                    message(
                            "enterprise.pqa.runtimeVerification.process.resourceNextAction",
                            "Review the sealed runtime evidence before official inspection."),
                    result,
                    operatorId,
                    "Protected resource prerequisite completed from selected sealed evidence.");
        }
        if (shouldCompletePrerequisite(steps, PromptQualityProcessCodes.RUNTIME_EVIDENCE)) {
            String evidenceState = runtimeEvidenceState(pkg, integrityValid, promptConsistency);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("packageId", pkg.getPackageId());
            result.put("sealed", pkg.isSealed());
            result.put("integrityValid", integrityValid);
            result.put("promptConsistencyState", promptConsistency == null ? null : promptConsistency.state());
            processRunService.completeStep(
                    processScope,
                    PromptQualityProcessCodes.RUNTIME_EVIDENCE,
                    PromptQualityStateDimension.RUNTIME_EVIDENCE.name(),
                    evidenceState,
                    pkg.getPackageId(),
                    runtimeEvidenceRoute(pkg.getPackageId(), processScope),
                    message(
                            "enterprise.pqa.runtimeVerification.process.evidenceResolved",
                            "Selected sealed runtime evidence is connected to this official inspection."),
                    message(
                            "enterprise.pqa.runtimeVerification.process.evidenceNextAction",
                            "Run official inspection with this packageId."),
                    result,
                    operatorId,
                    "Runtime evidence prerequisite completed from selected sealed evidence.");
        }
    }

    private boolean shouldCompletePrerequisite(List<PromptQualityProcessStepSnapshot> steps, String stepCode) {
        if (steps == null || steps.isEmpty()) {
            return true;
        }
        return steps.stream()
                .filter(step -> stepCode.equals(step.stepCode()))
                .findFirst()
                .map(step -> {
                    String state = step.executionState() == null ? "" : step.executionState().trim().toUpperCase(Locale.ROOT);
                    return !PromptQualityProcessCodes.COMPLETED.equals(state);
                })
                .orElse(true);
    }

    private String runtimeEvidenceState(
            SealedEvidencePackage pkg,
            boolean integrityValid,
            RuntimeEvidencePromptConsistencyResult promptConsistency) {
        if (pkg == null || !pkg.isSealed()) {
            return "UNSEALED";
        }
        if (!integrityValid) {
            return "INTEGRITY_ERROR";
        }
        if (promptConsistency != null && (!promptConsistency.passed() || promptConsistency.blocking())) {
            return "WARNING_SIGNALS";
        }
        return "READY_FOR_INSPECTION";
    }

    private String resourceDetailRoute(PromptQualityProcessScope scope) {
        return "/contexa/admin/prompt-quality/resources/detail"
                + "?resourceUrl=" + encode(scope.resourceUrl())
                + "&resourceId=" + encode(scope.resourceId())
                + "&httpMethod=" + encode(scope.httpMethod());
    }

    private String runtimeEvidenceRoute(String packageId, PromptQualityProcessScope scope) {
        StringBuilder route = new StringBuilder("/contexa/admin/prompt-quality/runtime-evidence?");
        appendRouteParam(route, "packageId", packageId);
        appendResourceScope(route, scope);
        return queryRoute(route);
    }

    private String verificationReadinessRoute(
            String packageId,
            PromptQualityProcessScope scope,
            String aggregateRunId) {
        StringBuilder route = new StringBuilder("/contexa/admin/prompt-quality/verification/readiness?");
        appendRouteParam(route, "packageId", packageId);
        appendRouteParam(route, "aggregateRunId", aggregateRunId);
        appendResourceScope(route, scope);
        return queryRoute(route);
    }

    private String verificationMetricsRoute(
            String packageId,
            PromptQualityProcessScope scope,
            String aggregateRunId) {
        StringBuilder route = new StringBuilder("/contexa/admin/prompt-quality/verification/metrics?");
        appendRouteParam(route, "packageId", packageId);
        appendRouteParam(route, "aggregateRunId", aggregateRunId);
        appendResourceScope(route, scope);
        return queryRoute(route);
    }

    private void appendResourceScope(StringBuilder route, PromptQualityProcessScope scope) {
        if (scope == null) {
            return;
        }
        appendRouteParam(route, "resourceUrl", scope.resourceUrl());
        appendRouteParam(route, "resourceId", scope.resourceId());
        appendRouteParam(route, "httpMethod", scope.httpMethod());
    }

    private void appendRouteParam(StringBuilder route, String name, String value) {
        if (!StringUtils.hasText(value)) {
            return;
        }
        if (route.charAt(route.length() - 1) != '?') {
            route.append('&');
        }
        route.append(name).append('=').append(encode(value));
    }

    private String queryRoute(StringBuilder route) {
        if (route.charAt(route.length() - 1) == '?') {
            return route.substring(0, route.length() - 1);
        }
        return route.toString();
    }

    private String encode(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }

    private List<OfficialRunFailureCause> failureCauses(List<RuntimeEvidenceMetricResult> metrics) {
        if (metrics == null || metrics.isEmpty()) {
            return List.of();
        }
        List<OfficialRunFailureCause> result = new ArrayList<>();
        for (RuntimeEvidenceMetricResult metric : metrics) {
            if (metric == null || metric.checks() == null) {
                continue;
            }
            for (RuntimeEvidenceCheckResult check : metric.checks()) {
                if (check == null
                        || check.pass()
                        || runtimeInputReadinessNotReady(check)
                        || !customerPromptQualityCheck(check)) {
                    continue;
                }
                result.add(new OfficialRunFailureCause(
                        metric.metricCode(),
                        metric.metricName(),
                        metric.officialRunId(),
                        check.checkCode(),
                        check.label(),
                        check.expectedValue(),
                        check.actualValue(),
                        check.source(),
                        check.remediationOwner(),
                        StringUtils.hasText(check.operatorReason())
                                ? check.operatorReason()
                                : message(
                                        "enterprise.pqa.runtimeVerification.failure.rootCauseTpl",
                                        "In {0}, expected value {1} and actual value {2} did not match.",
                                        check.label(),
                                        check.expectedValue(),
                                        check.actualValue()),
                        StringUtils.hasText(check.nextAction())
                                ? check.nextAction()
                                : message(
                                        "enterprise.pqa.runtimeVerification.failure.remediation",
                                        "Fix the source data that creates this prompt field, request the protected resource again, and reverify with the new evidence packageId."),
                        StringUtils.hasText(check.reverifyCriterion())
                                ? check.reverifyCriterion()
                                : check.label()));
            }
        }
        return result;
    }

    private List<RuntimeEvidenceMetricResult> issueMetrics(
            List<RuntimeEvidenceMetricResult> officialMetrics,
            RuntimeEvidencePromptConsistencyResult promptConsistency) {
        if (promptConsistency == null || promptConsistency.passed()) {
            return officialMetrics;
        }
        List<RuntimeEvidenceMetricResult> result = new ArrayList<>(officialMetrics == null ? List.of() : officialMetrics);
        result.add(new RuntimeEvidenceMetricResult(
                DefaultRuntimeEvidencePromptConsistencyGate.ISSUE_METRIC_CODE,
                null,
                message("enterprise.pqa.promptConsistency.metricName", "Evidence and prompt consistency"),
                message("enterprise.pqa.promptConsistency.metricGroup", "Pre-inspection gate"),
                0.0d,
                promptConsistency.state(),
                promptConsistency.stateLabel(),
                (int) promptConsistency.checks().stream().filter(RuntimeEvidenceCheckResult::pass).count(),
                promptConsistency.checks().size(),
                promptConsistency.checks()));
        return result;
    }

    private List<OfficialVerificationPromptComparison> executionComparisons(
            SealedEvidencePackage pkg,
            String requestId,
            String requestPath,
            String resourceId,
            String promptHash,
            String contextHash,
            Map<String, Object> requestFacts,
            Map<String, Object> authState,
            Map<String, Object> promptMetadata,
            Map<String, Object> decision,
            List<? extends OfficialVerificationRunView> runViews) {
        List<OfficialVerificationPromptComparison> finalPromptMetricComparisons =
                finalPromptMetricComparisons(runViews);
        List<OfficialVerificationPromptComparison> manifestComparisons =
                promptEvidenceManifestComparisons(pkg);
        if (finalPromptMetricComparisons.isEmpty() && manifestComparisons.isEmpty()) {
            return List.of();
        }
        Map<String, OfficialVerificationPromptComparison> comparisons = new LinkedHashMap<>();
        for (OfficialVerificationPromptComparison comparison : manifestComparisons) {
            if (comparison == null || !StringUtils.hasText(comparison.fieldKey())) {
                continue;
            }
            comparisons.put(
                    promptComparisonDedupeKey(comparison.fieldKey(), comparison.state()),
                    comparison);
        }
        for (OfficialVerificationPromptComparison comparison : finalPromptMetricComparisons) {
            if (comparison == null || !StringUtils.hasText(comparison.fieldKey())) {
                continue;
            }
            comparisons.merge(
                    promptComparisonDedupeKey(comparison.fieldKey(), comparison.state()),
                    comparison,
                    this::mergePromptMetricComparison);
        }
        return List.copyOf(comparisons.values());
    }

    private List<OfficialVerificationPromptComparison> finalPromptMetricComparisons(
            List<? extends OfficialVerificationRunView> runViews) {
        if (runViews == null || runViews.isEmpty()) {
            return List.of();
        }
        Map<String, OfficialVerificationPromptComparison> comparisons = new LinkedHashMap<>();
        for (OfficialVerificationRunView runView : runViews) {
            if (runView == null) {
                continue;
            }
            String metricCode = normalizedCode(runView.endpointKey());
            if (internalGateMetric(metricCode)) {
                continue;
            }
            for (OfficialVerificationCheckResultView check : runView.checks() == null
                    ? List.<OfficialVerificationCheckResultView>of()
                    : runView.checks()) {
                if (check == null
                        || check.pass()
                        || finalPromptInputReadinessNotReady(check)
                        || !customerPromptQualityCheck(check)) {
                    continue;
                }
                String fieldKey = finalPromptMetricFieldKey(metricCode, check);
                String state = finalPromptMetricState(check);
                String dedupeKey = promptComparisonDedupeKey(fieldKey, state);
                OfficialVerificationPromptComparison incoming = new OfficialVerificationPromptComparison(
                        fieldKey,
                        firstNonBlank(check.label(), fieldKey),
                        firstNonBlank(check.expectedValue(), ""),
                        firstNonBlank(check.actualValue(), ""),
                        firstNonBlank(check.expectedValue(), ""),
                        state,
                        comparisonStateLabel(state),
                        firstNonBlank(check.operatorReason(), check.actualValue(), check.label()),
                        StringUtils.hasText(metricCode) ? List.of(metricCode) : List.of(),
                        List.of(firstNonBlank(check.checkCode(), fieldKey)),
                        List.of(),
                        List.of(),
                        List.of(),
                        firstNonBlank(check.source(), "finalUserPrompt"),
                        "sealedEvidence.userPromptText",
                        firstNonBlank(check.remediationOwner(), remediationOwnerForMetric(metricCode)),
                        "FINAL_USER_PROMPT_METRIC_CHECK");
                comparisons.merge(dedupeKey, incoming, this::mergePromptMetricComparison);
            }
        }
        return List.copyOf(comparisons.values());
    }

    private OfficialVerificationPromptComparison mergePromptMetricComparison(
            OfficialVerificationPromptComparison existing,
            OfficialVerificationPromptComparison incoming) {
        if (existing == null) {
            return incoming;
        }
        if (incoming == null) {
            return existing;
        }
        return new OfficialVerificationPromptComparison(
                firstNonBlank(existing.fieldKey(), incoming.fieldKey()),
                firstNonBlank(existing.fieldLabel(), incoming.fieldLabel()),
                firstNonBlank(existing.sealedEvidenceValue(), incoming.sealedEvidenceValue()),
                firstNonBlank(existing.promptValue(), incoming.promptValue()),
                firstNonBlank(existing.officialFactValue(), incoming.officialFactValue()),
                firstNonBlank(existing.state(), incoming.state()),
                firstNonBlank(existing.stateLabel(), incoming.stateLabel()),
                firstNonBlank(existing.meaning(), incoming.meaning()),
                union(existing.metricCodes(), incoming.metricCodes()),
                union(existing.checkCodes(), incoming.checkCodes()),
                union(existing.findingIds(), incoming.findingIds()),
                union(existing.issueIds(), incoming.issueIds()),
                union(existing.remediationGroupIds(), incoming.remediationGroupIds()),
                firstNonBlank(existing.promptLocation(), incoming.promptLocation()),
                firstNonBlank(existing.evidenceSource(), incoming.evidenceSource()),
                firstNonBlank(existing.recommendedOwner(), incoming.recommendedOwner()),
                firstNonBlank(existing.canonicalSource(), incoming.canonicalSource()));
    }

    private List<String> union(List<String> left, List<String> right) {
        List<String> result = new ArrayList<>();
        for (String value : left == null ? List.<String>of() : left) {
            if (StringUtils.hasText(value) && !result.contains(value.trim())) {
                result.add(value.trim());
            }
        }
        for (String value : right == null ? List.<String>of() : right) {
            if (StringUtils.hasText(value) && !result.contains(value.trim())) {
                result.add(value.trim());
            }
        }
        return List.copyOf(result);
    }

    private String finalPromptMetricFieldKey(String metricCode, OfficialVerificationCheckResultView check) {
        String source = safe(check == null ? null : check.source());
        if (StringUtils.hasText(source)
                && (source.startsWith("finalUserPrompt") || source.startsWith("finalSystemPrompt"))) {
            return source;
        }
        throw new IllegalStateException("공식검사 지표 실패 항목이 final userPrompt 위치를 제공하지 않았습니다. "
                + "metricCode=" + safe(metricCode)
                + ", checkCode=" + safe(check == null ? null : check.checkCode())
                + ", source=" + source);
    }

    private String finalPromptMetricState(OfficialVerificationCheckResultView check) {
        if (finalPromptInputReadinessNotReady(check)) {
            return "INPUT_NOT_READY";
        }
        String failureType = firstNonBlank(check == null ? null : check.failureType(), "");
        if ("INPUT_NOT_READY".equalsIgnoreCase(failureType)) {
            return "PROMPT_PURPOSE_NOT_SATISFIED";
        }
        String purposeResult = firstNonBlank(check == null ? null : check.purposeResult(), "");
        if ("NOT_EVALUATED_INPUT_NOT_READY".equalsIgnoreCase(purposeResult)
                || "INPUT_NOT_READY".equalsIgnoreCase(purposeResult)) {
            return "INPUT_NOT_READY";
        }
        return firstNonBlank(failureType, purposeResult, "CONTRACT_MISMATCH");
    }

    private boolean finalPromptInputReadinessNotReady(OfficialVerificationCheckResultView check) {
        if (check == null) {
            return false;
        }
        String readiness = safe(check.inputReadinessState()).toUpperCase(Locale.ROOT);
        String purpose = safe(check.purposeResult()).toUpperCase(Locale.ROOT);
        String failure = safe(check.failureType()).toUpperCase(Locale.ROOT);
        if ("NOT_READY".equals(readiness) || "INPUT_NOT_READY".equals(readiness)
                || "NOT_EVALUATED_INPUT_NOT_READY".equals(purpose) || "INPUT_NOT_READY".equals(purpose)) {
            return true;
        }
        if (!"INPUT_NOT_READY".equals(failure)) {
            return false;
        }
        String text = safe(check.actualValue()) + " " + safe(check.operatorReason());
        String normalized = text.toLowerCase(Locale.ROOT);
        return normalized.contains("missing:")
                || normalized.contains("missing inputs")
                || normalized.contains("누락:");
    }

    private String remediationOwnerForMetric(String metricCode) {
        return switch (normalizedCode(metricCode)) {
            case "BMA", "USNS" -> "학습 기준선 생산자";
            case "BSR" -> "행동 컨텍스트 생산자";
            case "COR", "RAP" -> "RAG 권한 필터";
            case "PFR", "MTR" -> "프롬프트 캡처기";
            case "PRE" -> "보호 리소스 등록기";
            case "RPI" -> "재검증 공정";
            case "EIR", "CCR", "CCSR" -> "컨텍스트 조립기";
            default -> "PQA 공식검사";
        };
    }

    private List<OfficialVerificationPromptComparison> promptEvidenceManifestComparisons(SealedEvidencePackage pkg) {
        Map<String, Object> manifest = parseJson(pkg == null ? null : pkg.getPromptEvidenceManifestJson());
        Object fields = manifest.get("fields");
        Map<String, OfficialVerificationPromptComparison> resultByComparisonKey = new LinkedHashMap<>();
        if (fields instanceof List<?> rows) {
            for (Object row : rows) {
                if (!(row instanceof Map<?, ?> map)) {
                    continue;
                }
                String fieldKey = stringValue(map.get("fieldKey"));
                if (!StringUtils.hasText(fieldKey)) {
                    continue;
                }
                String promptValue = stringValue(map.get("promptValue"));
                String evidenceValue = stringValue(map.get("evidenceValue"));
                String projectionState = stringValue(map.get("projectionState"));
                String requiredLevel = stringValue(map.get("requiredLevel"));
                String comparisonState = comparisonStateFromProjectionState(projectionState, requiredLevel);
                putPromptComparison(resultByComparisonKey, new OfficialVerificationPromptComparison(
                        fieldKey,
                        firstNonBlank(stringValue(map.get("displayName")), fieldLabel(fieldKey, fieldKey)),
                        evidenceValue,
                        promptValue,
                        evidenceValue,
                        comparisonState,
                        comparisonStateLabel(comparisonState),
                        comparisonMeaning(comparisonState),
                        stringList(map.get("metricCodes")),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        manifestPromptLocation(map),
                        manifestEvidenceSource(map),
                        stringValue(map.get("producer")),
                        "USER_PROMPT_EVIDENCE_MANIFEST"));
            }
        }
        Object fieldStateLedger = manifest.get("fieldStateLedger");
        if (fieldStateLedger instanceof List<?> rows) {
            for (Object row : rows) {
                if (!(row instanceof Map<?, ?> map)) {
                    continue;
                }
                String fieldKey = stringValue(map.get("fieldKey"));
                if (!StringUtils.hasText(fieldKey)) {
                    continue;
                }
                String sourceType = stringValue(map.get("sourceType"));
                String fieldState = stringValue(map.get("fieldState"));
                String label = firstNonBlank(
                        stringValue(map.get("promptLabel")),
                        stringValue(map.get("sourceFieldPath")),
                        fieldKey);
                String value = stringValue(map.get("valuePreview"));
                boolean finalUserPromptField = "FINAL_USER_PROMPT_FIELD".equals(sourceType);
                boolean blockingCandidate = Boolean.TRUE.equals(map.get("blockingCandidate"));
                if (!finalUserPromptField && !blockingCandidate) {
                    continue;
                }
                String comparisonState = blockingCandidate
                        ? promptProblemStateFromFieldState(map)
                        : "MATCH";
                putPromptComparison(resultByComparisonKey, new OfficialVerificationPromptComparison(
                        fieldKey,
                        fieldLabel(fieldKey, label),
                        value,
                        value,
                        value,
                        comparisonState,
                        comparisonStateLabel(comparisonState),
                        firstNonBlank(stringValue(map.get("absenceReasonText")), comparisonMeaning(comparisonState)),
                        metricCodesForFieldState(map),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        firstNonBlank(stringValue(map.get("promptSection")), stringValue(map.get("promptPresenceState"))),
                        stringValue(map.get("sourceFieldPath")),
                        firstNonBlank(stringValue(map.get("remediationOwner")), "PROMPT_ASSEMBLER"),
                        "PROMPT_FIELD_STATE_LEDGER"));
            }
        }
        addPromptExecutionMetadataProblemComparisons(resultByComparisonKey, pkg);
        return List.copyOf(resultByComparisonKey.values());
    }

    private void putPromptComparison(
            Map<String, OfficialVerificationPromptComparison> resultByComparisonKey,
            OfficialVerificationPromptComparison candidate) {
        if (candidate == null || !StringUtils.hasText(candidate.fieldKey())) {
            return;
        }
        String key = promptComparisonDedupeKey(candidate.fieldKey(), candidate.state());
        OfficialVerificationPromptComparison existing = resultByComparisonKey.get(key);
        if (existing == null
                || (!blockingPromptComparison(existing) && blockingPromptComparison(candidate))) {
            resultByComparisonKey.put(key, candidate);
        }
    }

    private String promptComparisonDedupeKey(String fieldKey, String state) {
        return safe(fieldKey).trim() + "|" + safe(firstNonBlank(state, "MATCH")).toUpperCase(Locale.ROOT);
    }

    private String comparisonStateFromFieldState(String fieldState) {
        String normalized = safe(fieldState).toUpperCase(Locale.ROOT);
        if (!StringUtils.hasText(normalized)) {
            return "MATCH";
        }
        return switch (normalized) {
            case "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING" -> "PROMPT_MISSING";
            case "UNKNOWN_WITHOUT_REASON", "CONTRACT_MISMATCH" -> "VALUE_MISMATCH";
            default -> "VALUE_MISMATCH";
        };
    }

    private void addPromptExecutionMetadataProblemComparisons(
            Map<String, OfficialVerificationPromptComparison> resultByComparisonKey,
            SealedEvidencePackage pkg) {
        Map<String, Object> promptMetadata = parseJson(pkg == null ? null : pkg.getPromptExecutionMetadataJson());
        addPromptFinalUserFieldLedgerComparisons(resultByComparisonKey, promptMetadata.get("promptFinalUserFieldLedger"));
        addPromptUserFieldDiffLedgerComparisons(resultByComparisonKey, promptMetadata.get("promptUserFieldDiffLedger"));
    }

    private void addPromptFinalUserFieldLedgerComparisons(
            Map<String, OfficialVerificationPromptComparison> resultByComparisonKey,
            Object ledger) {
        if (!(ledger instanceof List<?> rows)) {
            return;
        }
        for (Object row : rows) {
            if (!(row instanceof Map<?, ?> map)) {
                continue;
            }
            String fieldKey = stringValue(map.get("fieldKey"));
            if (!StringUtils.hasText(fieldKey)) {
                continue;
            }
            String comparisonState = promptProblemStateFromPromptField(map);
            if (!StringUtils.hasText(comparisonState)) {
                continue;
            }
            String label = firstNonBlank(stringValue(map.get("label")), fieldKey);
            String section = firstNonBlank(
                    stringValue(map.get("sectionTitle")),
                    stringValue(map.get("sectionKey")),
                    "userPrompt");
            putPromptComparison(resultByComparisonKey, new OfficialVerificationPromptComparison(
                    fieldKey,
                    fieldLabel(fieldKey, label),
                    stringValue(map.get("valuePreview")),
                    stringValue(map.get("valuePreview")),
                    stringValue(map.get("valuePreview")),
                    comparisonState,
                    comparisonStateLabel(comparisonState),
                    firstNonBlank(stringValue(map.get("absenceReasonText")), comparisonMeaning(comparisonState)),
                    stringList(map.get("metricCodes")),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    section,
                    "sealedEvidence.promptExecutionMetadata.promptFinalUserFieldLedger",
                    firstNonBlank(stringValue(map.get("remediationOwner")), "PROMPT_ASSEMBLER"),
                    "PROMPT_FINAL_USER_FIELD_LEDGER"));
        }
    }

    private void addPromptUserFieldDiffLedgerComparisons(
            Map<String, OfficialVerificationPromptComparison> resultByComparisonKey,
            Object ledger) {
        if (!(ledger instanceof List<?> rows)) {
            return;
        }
        for (Object row : rows) {
            if (!(row instanceof Map<?, ?> map)) {
                continue;
            }
            String fieldKey = stringValue(map.get("fieldKey"));
            if (!StringUtils.hasText(fieldKey)) {
                continue;
            }
            String diffType = firstNonBlank(stringValue(map.get("diffType")), stringValue(map.get("problemType")));
            boolean blocking = Boolean.TRUE.equals(map.get("blockingCandidate"))
                    || Boolean.TRUE.equals(map.get("officialBlockingCandidate"))
                    || "MISSING_IN_FINAL_PROMPT".equalsIgnoreCase(diffType)
                    || "VALUE_CHANGED".equalsIgnoreCase(diffType);
            if (!blocking) {
                continue;
            }
            String comparisonState = "MISSING_IN_FINAL_PROMPT".equalsIgnoreCase(diffType)
                    || "VALUE_CHANGED".equalsIgnoreCase(diffType)
                    ? "CONTRACT_MISMATCH"
                    : firstNonBlank(stringValue(map.get("problemType")), "PROMPT_COMPACTED_SIGNAL");
            String label = firstNonBlank(stringValue(map.get("label")), fieldKey);
            String section = firstNonBlank(
                    stringValue(map.get("sectionTitle")),
                    stringValue(map.get("sectionKey")),
                    "userPrompt");
            putPromptComparison(resultByComparisonKey, new OfficialVerificationPromptComparison(
                    fieldKey,
                    fieldLabel(fieldKey, label),
                    firstNonBlank(stringValue(map.get("rawValuePreview")), stringValue(map.get("reason"))),
                    firstNonBlank(stringValue(map.get("finalValuePreview")), stringValue(map.get("reason"))),
                    firstNonBlank(stringValue(map.get("rawValuePreview")), stringValue(map.get("finalValuePreview"))),
                    comparisonState,
                    comparisonStateLabel(comparisonState),
                    firstNonBlank(stringValue(map.get("reason")), comparisonMeaning(comparisonState)),
                    stringList(map.get("metricCodes")),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    section,
                    "sealedEvidence.promptExecutionMetadata.promptUserFieldDiffLedger",
                    firstNonBlank(stringValue(map.get("remediationOwner")), "PROMPT_ASSEMBLER"),
                    "PROMPT_USER_FIELD_DIFF_LEDGER"));
        }
    }

    private String promptProblemStateFromPromptField(Map<?, ?> row) {
        String explicitProblemType = firstNonBlank(stringValue(row.get("problemType")), "");
        if (StringUtils.hasText(explicitProblemType)) {
            return explicitProblemType.toUpperCase(Locale.ROOT);
        }
        String fieldState = stringValue(row.get("fieldState"));
        String stateProblem = promptProblemStateFromFieldState(row);
        if (actualPromptProblemState(stateProblem)) {
            return stateProblem;
        }
        String projectionState = stringValue(row.get("projectionState"));
        if ("MISSING".equalsIgnoreCase(projectionState)
                || "MISSING_IN_PROMPT".equalsIgnoreCase(projectionState)
                || "VALUE_MISMATCH".equalsIgnoreCase(projectionState)) {
            return "CONTRACT_MISMATCH";
        }
        if (Boolean.TRUE.equals(row.get("compactedMarker"))
                || Boolean.TRUE.equals(row.get("truncatedMarker"))
                || "COMPACTED_WITH_FULL_SOURCE".equalsIgnoreCase(fieldState)) {
            return "PROMPT_COMPACTED_SIGNAL";
        }
        return "";
    }

    private String promptProblemStateFromFieldState(Map<?, ?> row) {
        String explicitProblemType = firstNonBlank(stringValue(row.get("problemType")), "");
        if (StringUtils.hasText(explicitProblemType)) {
            return explicitProblemType.toUpperCase(Locale.ROOT);
        }
        String fieldState = safe(stringValue(row.get("fieldState"))).toUpperCase(Locale.ROOT);
        if (actualPromptProblemState(fieldState)) {
            return fieldState;
        }
        return comparisonStateFromFieldState(fieldState);
    }

    private boolean actualPromptProblemState(String state) {
        return Set.of(
                        "PROMPT_MISSING",
                        "FACT_MISSING",
                        "VALUE_MISMATCH",
                        "CONTRACT_MISMATCH",
                        "REQUIRED_MISSING",
                        "CONDITIONAL_REQUIRED_MISSING",
                        "UNKNOWN_WITHOUT_REASON",
                        "PROMPT_COMPACTED_SIGNAL",
                        "PRODUCER_NOT_AVAILABLE",
                        "PROVISIONAL_EVIDENCE",
                        "NO_DIRECT_COMPARABLE",
                        "BASELINE_MISMATCH_SIGNAL")
                .contains(safe(state).toUpperCase(Locale.ROOT));
    }

    private List<String> metricCodesForFieldState(Map<?, ?> row) {
        List<String> metricCodes = stringList(row.get("metricCodes"));
        if (!metricCodes.isEmpty()) {
            return metricCodes;
        }
        return List.of();
    }

    private String comparisonStateFromProjectionState(String projectionState) {
        return comparisonStateFromProjectionState(projectionState, "");
    }

    private String comparisonStateFromProjectionState(String projectionState, String requiredLevel) {
        String normalizedLevel = safe(requiredLevel).toUpperCase(Locale.ROOT);
        String normalizedState = safe(projectionState).toUpperCase(Locale.ROOT);
        if (!"P0_REQUIRED".equals(normalizedLevel)
                && (normalizedState.equals("MISSING_IN_PROMPT")
                || normalizedState.equals("MISSING_IN_EVIDENCE")
                || normalizedState.equals("MISSING_IN_BOTH")
                || normalizedState.equals("DECLARED_ABSENCE"))) {
            return "NOT_APPLICABLE";
        }
        return switch (safe(projectionState).toUpperCase(Locale.ROOT)) {
            case "PRESENT" -> "MATCH";
            case "MISSING_IN_PROMPT" -> "PROMPT_MISSING";
            case "MISSING_IN_EVIDENCE" -> "FACT_MISSING";
            case "MISSING_IN_BOTH", "DECLARED_ABSENCE" -> "NOT_APPLICABLE";
            case "VALUE_MISMATCH" -> "VALUE_MISMATCH";
            default -> "VALUE_MISMATCH";
        };
    }

    private String manifestEvidenceSource(Map<?, ?> row) {
        String section = stringValue(row.get("evidenceSection"));
        String path = stringValue(row.get("evidencePath"));
        if (!StringUtils.hasText(section)) {
            return path;
        }
        String normalizedSection = section.toLowerCase(Locale.ROOT).replace('_', '.');
        return StringUtils.hasText(path) ? "sealedEvidence." + normalizedSection + "." + path : "sealedEvidence." + normalizedSection;
    }

    private String manifestPromptLocation(Map<?, ?> row) {
        String explicitLocation = firstNonBlank(
                stringValue(row.get("promptLocation")),
                stringValue(row.get("promptSection")));
        if (StringUtils.hasText(explicitLocation)) {
            return explicitLocation;
        }
        String evidenceSection = stringValue(row.get("evidenceSection"));
        if (!StringUtils.hasText(evidenceSection)) {
            return "userPrompt";
        }
        return switch (evidenceSection.trim().toUpperCase(Locale.ROOT)) {
            case "REQUEST_FACTS", "AUTH_STATE", "DECISION" -> "userPrompt.requestContext";
            case "BASELINE_SNAPSHOT", "CANONICAL_CONTEXT" -> "userPrompt.baseline";
            case "RAG_RESULTS" -> "userPrompt.rag";
            case "PROMPT_EXECUTION_METADATA" -> "promptExecutionMetadata";
            default -> "userPrompt";
        };
    }

    private List<String> stringList(Object value) {
        if (value instanceof List<?> list) {
            return list.stream()
                    .map(this::stringValue)
                    .filter(StringUtils::hasText)
                    .distinct()
                    .toList();
        }
        String single = stringValue(value);
        return StringUtils.hasText(single) ? List.of(single) : List.of();
    }

    private String stringValue(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    private int integerValue(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            try {
                return Integer.parseInt(text.trim());
            }
            catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    private String comparisonState(String sealedEvidenceValue, String officialFactValue, String promptValue) {
        boolean sealedMissing = !StringUtils.hasText(sealedEvidenceValue);
        boolean officialMissing = !StringUtils.hasText(officialFactValue);
        boolean promptMissing = !StringUtils.hasText(promptValue);
        if (sealedMissing && officialMissing && promptMissing) {
            return "NOT_APPLICABLE";
        }
        if (!sealedMissing && promptMissing) {
            return "PROMPT_MISSING";
        }
        if (!sealedMissing && officialMissing) {
            return "FACT_MISSING";
        }
        boolean matches = StringUtils.hasText(sealedEvidenceValue)
                && StringUtils.hasText(officialFactValue)
                && StringUtils.hasText(promptValue)
                && clean(sealedEvidenceValue).equalsIgnoreCase(clean(officialFactValue))
                && clean(sealedEvidenceValue).equalsIgnoreCase(clean(promptValue));
        return matches ? "MATCH" : "VALUE_MISMATCH";
    }

    private String comparisonStateLabel(String state) {
        return switch (state) {
            case "MATCH" -> message("enterprise.pqa.officialRun.comparison.state.match", "Match");
            case "PROMPT_MISSING" -> message("enterprise.pqa.officialRun.comparison.state.promptMissing", "Missing from prompt");
            case "FACT_MISSING" -> message("enterprise.pqa.officialRun.comparison.state.factMissing", "Missing from core fact");
            case "VALUE_MISMATCH" -> message("enterprise.pqa.officialRun.comparison.state.valueMismatch", "Value mismatch");
            case "CONTRACT_MISMATCH" -> message("enterprise.pqa.officialRun.comparison.state.contractMismatch", "Contract mismatch");
            case "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING" -> message("enterprise.pqa.officialRun.comparison.state.requiredMissing", "Required field missing");
            case "UNKNOWN_WITHOUT_REASON" -> message("enterprise.pqa.officialRun.comparison.state.unknownWithoutReason", "Unknown without reason");
            case "PROMPT_COMPACTED_SIGNAL" -> message("enterprise.pqa.officialRun.comparison.state.compactedSignal", "Prompt compaction requires evidence");
            case "PRODUCER_NOT_AVAILABLE" -> message("enterprise.pqa.officialRun.comparison.state.producerUnavailable", "Context producer unavailable");
            case "PROVISIONAL_EVIDENCE" -> message("enterprise.pqa.officialRun.comparison.state.provisionalEvidence", "Provisional evidence");
            case "NO_DIRECT_COMPARABLE" -> message("enterprise.pqa.officialRun.comparison.state.noComparable", "No direct comparable history");
            case "BASELINE_MISMATCH_SIGNAL" -> message("enterprise.pqa.officialRun.comparison.state.baselineMismatch", "Baseline mismatch signal");
            case "NOT_APPLICABLE" -> message("enterprise.pqa.officialRun.comparison.state.notApplicable", "Not applicable");
            default -> message("enterprise.pqa.officialRun.comparison.state.unknown", "Review");
        };
    }

    private String comparisonMeaning(String state) {
        return switch (state) {
            case "MATCH" -> message(
                    "enterprise.pqa.officialRun.comparison.meaning.match",
                    "The sealed evidence, prompt, and core official fact match.");
            case "PROMPT_MISSING" -> message(
                    "enterprise.pqa.officialRun.comparison.meaning.promptMissing",
                    "A sealed evidence value is not visible in the final prompt.");
            case "FACT_MISSING" -> message(
                    "enterprise.pqa.officialRun.comparison.meaning.factMissing",
                    "A sealed evidence value is missing from the core official fact ledger.");
            case "VALUE_MISMATCH" -> message(
                    "enterprise.pqa.officialRun.comparison.meaning.valueMismatch",
                    "A value differs across sealed evidence, prompt, or core official fact.");
            case "CONTRACT_MISMATCH" -> "The final prompt, raw prompt, and sealed evidence contract are not synchronized.";
            case "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING" -> "A required prompt evidence field is missing or lacks an allowed absence reason.";
            case "UNKNOWN_WITHOUT_REASON" -> "The prompt contains an unknown state without a recorded reason.";
            case "PROMPT_COMPACTED_SIGNAL" -> "Prompt compaction changed or removed a field without a complete field-level lineage.";
            case "PRODUCER_NOT_AVAILABLE" -> "A required context producer did not provide this field.";
            case "PROVISIONAL_EVIDENCE" -> "Provisional evidence is present and must not be treated as confirmed evidence.";
            case "NO_DIRECT_COMPARABLE" -> "The prompt lacks direct comparable history for this field.";
            case "BASELINE_MISMATCH_SIGNAL" -> "The prompt contains a baseline mismatch signal that must be explained and linked.";
            case "NOT_APPLICABLE" -> message(
                    "enterprise.pqa.officialRun.comparison.meaning.notApplicable",
                    "This value is not applicable to this package.");
            default -> message(
                    "enterprise.pqa.officialRun.comparison.meaning.default",
                    "Review this field.");
        };
    }

    private String methodValue(Map<String, Object> requestFacts) {
        return firstNonBlank(text(requestFacts, "httpMethod"), text(requestFacts, "method"));
    }

    private String bool(boolean value) {
        return String.valueOf(value);
    }

    private String clean(String value) {
        return value == null ? "" : value.trim();
    }

    private String fieldLabel(String key, String fallback) {
        return message("enterprise.pqa.officialRun.field." + key, fallback);
    }

    private ScorecardResult safeScorecard(SealedEvidencePackage pkg) {
        try {
            return promptScorecardService.evaluate(pkg);
        }
        catch (RuntimeException ignored) {
            return null;
        }
    }

    private DeterministicReplayResult safeReplay(SealedEvidencePackage pkg) {
        try {
            return replayService.replay(pkg.getPackageId());
        }
        catch (RuntimeException exception) {
            return new DeterministicReplayResult(
                    pkg.getPackageId(),
                    false,
                    pkg.getPromptHash(),
                    null,
                    1,
                    0,
                    List.of(message(
                            "enterprise.pqa.runtimeVerification.replay.failedTpl",
                            "Replay failed: {0}",
                            exception.getMessage())),
                    List.of(),
                    List.of(),
                    Instant.now());
        }
    }

    private List<RuntimeEvidenceMetricResult> toMetricResults(
            List<? extends OfficialVerificationRunView> runViews,
            List<OfficialVerificationPromptComparison> promptComparisons,
            String packageId,
            String aggregateRunId) {
        Map<String, List<OfficialVerificationPromptComparison>> promptComparisonsByMetric =
                promptComparisonsByMetric(promptComparisons);
        Map<String, OfficialVerificationRunView> runsByMetric = (runViews == null ? List.<OfficialVerificationRunView>of() : runViews).stream()
                .filter(run -> run != null && StringUtils.hasText(run.endpointKey()))
                .collect(Collectors.toMap(
                        run -> normalizedCode(run.endpointKey()),
                        run -> run,
                        (left, right) -> left,
                        LinkedHashMap::new));
        List<RuntimeEvidenceMetricResult> results = new ArrayList<>();
        for (OfficialVerificationMetricDefinition metric : metricCatalog.promptQualityMetrics()) {
            if (metric == null || !StringUtils.hasText(metric.code())) {
                continue;
            }
            String metricCode = normalizedCode(metric.code());
            OfficialVerificationRunView run = runsByMetric.get(metricCode);
            List<RuntimeEvidenceCheckResult> checks = new ArrayList<>();
            if (run != null) {
                for (OfficialVerificationCheckResultView check : run.checks() == null
                        ? List.<OfficialVerificationCheckResultView>of()
                        : run.checks()) {
                    if (!officialFinalPromptCheck(check)) {
                        continue;
                    }
                    checks.add(runtimeCheck(metricCode, check, true));
                }
            }
            if (run == null || run.checks() == null || run.checks().isEmpty()) {
                for (OfficialVerificationPromptComparison comparison :
                        promptComparisonsByMetric.getOrDefault(metricCode, List.of())) {
                    if (blockingPromptComparison(comparison)) {
                        checks.add(promptComparisonCheck(metricCode, comparison, packageId, aggregateRunId));
                    }
                }
            }
            List<RuntimeEvidenceCheckResult> evaluatedChecks = checks.stream()
                    .filter(check -> !notApplicableCheck(check))
                    .toList();
            int totalChecks = evaluatedChecks.size();
            int passedChecks = (int) evaluatedChecks.stream()
                    .filter(RuntimeEvidenceCheckResult::pass)
                    .count();
            boolean metricNotApplicable = "not_applicable".equalsIgnoreCase(run == null ? null : run.state())
                    || (!checks.isEmpty() && checks.stream().allMatch(this::notApplicableCheck));
            boolean metricPassed = !metricNotApplicable && passedChecks == totalChecks;
            String state = metricNotApplicable
                    ? "NOT_APPLICABLE"
                    : metricPassed
                    ? "SUCCESS"
                    : "threshold_failed";
            double score = totalChecks == 0
                    ? 100.0d
                    : Math.round(((double) passedChecks / (double) totalChecks) * 1000.0d) / 10.0d;
            results.add(new RuntimeEvidenceMetricResult(
                            metricCode,
                    run == null ? null : run.runId(),
                    narrativeCatalog.metricName(metricCode),
                    groupName(metric.category()),
                    score,
                    state,
                    metricNotApplicable
                            ? message("enterprise.pqa.runtimeVerification.metric.state.notApplicable", "Not applicable")
                            : metricPassed
                            ? message("enterprise.pqa.runtimeVerification.metric.state.passed", "Passed")
                            : message("enterprise.pqa.runtimeVerification.metric.state.blocked", "Blocked"),
                    passedChecks,
                    totalChecks,
                    List.copyOf(checks)));
        }
        return results;
    }

    @SuppressWarnings("unused")
    private List<RuntimeEvidenceMetricResult> toMetricResults(
            List<? extends OfficialVerificationRunView> runViews,
            Map<String, ?> unusedProblemLedger,
            List<OfficialVerificationPromptComparison> promptComparisons,
            String packageId,
            String aggregateRunId) {
        return toMetricResults(runViews, promptComparisons, packageId, aggregateRunId);
    }

    private boolean officialFinalPromptCheck(OfficialVerificationCheckResultView check) {
        if (check == null || !StringUtils.hasText(check.source())) {
            return false;
        }
        String source = check.source().trim();
        return source.startsWith("finalUserPrompt.")
                || source.startsWith("finalSystemPrompt.")
                || source.startsWith("internalGate.");
    }

    private boolean internalGateMetric(String metricCode) {
        return switch (normalizedCode(metricCode)) {
            case "MTR", "RPI", "PRE" -> true;
            default -> false;
        };
    }

    private RuntimeEvidenceCheckResult runtimeCheck(
            String metricCode,
            OfficialVerificationCheckResultView check,
            boolean preserveBlockingState) {
        boolean pass = check.pass() || !preserveBlockingState;
        return new RuntimeEvidenceCheckResult(
                metricCode,
                check.checkCode(),
                check.label(),
                check.expectedValue(),
                check.actualValue(),
                pass,
                check.source(),
                pass ? "INFO" : check.severity(),
                pass ? "" : check.failureType(),
                check.remediationOwner(),
                check.operatorReason(),
                check.nextAction(),
                check.reverifyCriterion(),
                check.issueKey(),
                check.customerVisible(),
                readinessScope(check),
                check.purposeVersion(),
                check.inputReadinessState(),
                check.purposeResult(),
                check.detectedSignalsJson(),
                check.interpretationLinksJson(),
                check.decisionUtility(),
                check.whyItMatters());
    }

    private boolean notApplicableCheck(RuntimeEvidenceCheckResult check) {
        return check != null && "NOT_APPLICABLE".equalsIgnoreCase(safe(check.purposeResult()));
    }

    private Map<String, List<OfficialVerificationPromptComparison>> promptComparisonsByMetric(
            List<OfficialVerificationPromptComparison> promptComparisons) {
        Map<String, List<OfficialVerificationPromptComparison>> result = new LinkedHashMap<>();
        if (promptComparisons == null) {
            return result;
        }
        for (OfficialVerificationPromptComparison comparison : promptComparisons) {
            if (comparison == null) {
                continue;
            }
            List<String> metricCodes = metricCodes(comparison);
            if (blockingPromptComparison(comparison) && metricCodes.isEmpty()) {
                throw new IllegalStateException("Actual prompt problem is not bound to a 12-metric code. fieldKey="
                        + firstNonBlank(comparison.fieldKey(), "unknown")
                        + ", state=" + firstNonBlank(comparison.state(), "unknown"));
            }
            if (blockingPromptComparison(comparison) && !StringUtils.hasText(comparison.recommendedOwner())) {
                throw new IllegalStateException("Actual prompt problem is not bound to a remediation owner. fieldKey="
                        + firstNonBlank(comparison.fieldKey(), "unknown")
                        + ", state=" + firstNonBlank(comparison.state(), "unknown"));
            }
            for (String metricCode : metricCodes) {
                result.computeIfAbsent(metricCode, ignored -> new ArrayList<>())
                        .add(comparison);
            }
        }
        return result;
    }

    private RuntimeEvidenceCheckResult promptComparisonCheck(
            String metricCode,
            OfficialVerificationPromptComparison comparison,
            String packageId,
            String aggregateRunId) {
        String label = firstNonBlank(comparison.fieldLabel(), comparison.fieldKey(), "Prompt field");
        String state = firstNonBlank(comparison.state(), "MATCH");
        boolean pass = !blockingPromptComparison(comparison);
        return new RuntimeEvidenceCheckResult(
                metricCode,
                pass
                        ? actualPromptComparisonId(packageId, aggregateRunId, comparison.fieldKey(), state)
                        : actualPromptProblemId(packageId, aggregateRunId, comparison.fieldKey(), state),
                label,
                expectedValueForPromptProblem(comparison),
                pass ? firstNonBlank(comparison.meaning(), "The field satisfies the prompt evidence contract.")
                        : actualValueForPromptProblem(comparison),
                pass,
                firstNonBlank(comparison.promptLocation(), comparison.evidenceSource(), comparison.fieldKey()),
                pass ? "INFO" : "BLOCKING",
                pass ? "" : state,
                firstNonBlank(comparison.recommendedOwner(), "PROMPT_ASSEMBLER"),
                firstNonBlank(comparison.meaning(), label + " field did not satisfy the prompt evidence contract."),
                pass ? "No action is required for this field."
                        : "Fix the source that creates this prompt field, collect new sealed evidence, and rerun official inspection.",
                pass ? "The same prompt field remains synchronized in the next official inspection."
                        : "The same prompt field must be recorded as matched or non-blocking in the next official inspection.",
                firstNonBlank(comparison.fieldKey(), comparison.promptLocation(), label),
                true,
                "CUSTOMER_PROMPT_QUALITY",
                "",
                "READY",
                pass ? "PURPOSE_PASSED" : "PURPOSE_FAILED",
                "[]",
                "[]",
                "",
                "");
    }

    private String expectedValueForPromptProblem(OfficialVerificationPromptComparison problem) {
        if (problem == null) {
            return "The actual prompt field must satisfy the sealed evidence contract.";
        }
        return switch (safe(problem.state()).toUpperCase(Locale.ROOT)) {
            case "PROMPT_MISSING" -> "The sealed evidence value must be visible in the final LLM user prompt.";
            case "FACT_MISSING" -> "The final LLM user prompt field must also be stored in the sealed evidence package.";
            case "VALUE_MISMATCH", "CONTRACT_MISMATCH" -> "The final LLM user prompt value and the sealed evidence value must match.";
            case "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING" -> "The required prompt evidence field must be present or have an allowed absence policy.";
            case "UNKNOWN_WITHOUT_REASON" -> "Unknown prompt evidence must include a recorded reason and remediation owner.";
            case "PROMPT_COMPACTED_SIGNAL" -> "Prompt compaction must preserve full source lineage and field-level diff evidence.";
            case "PRODUCER_NOT_AVAILABLE" -> "The required context producer must record its unavailable state and reason.";
            case "PROVISIONAL_EVIDENCE" -> "Provisional evidence must be explicitly labeled and not represented as confirmed evidence.";
            case "NO_DIRECT_COMPARABLE" -> "Comparable-history absence must be recorded as a bounded evidence limitation.";
            case "BASELINE_MISMATCH_SIGNAL" -> "Baseline mismatch signals must be visible and linked to the final prompt evidence.";
            default -> "The actual prompt field must satisfy the sealed evidence contract.";
        };
    }

    private String actualValueForPromptProblem(OfficialVerificationPromptComparison problem) {
        if (problem == null) {
            return "An actual prompt problem was recorded.";
        }
        return switch (safe(problem.state()).toUpperCase(Locale.ROOT)) {
            case "PROMPT_MISSING" -> "The final user prompt does not contain this value. sealedEvidenceValue="
                    + firstNonBlank(problem.sealedEvidenceValue(), "unavailable");
            case "FACT_MISSING" -> "The sealed evidence package does not contain this value. finalPromptValue="
                    + firstNonBlank(problem.promptValue(), "unavailable");
            case "VALUE_MISMATCH", "CONTRACT_MISMATCH" -> "The values do not match. finalPromptValue="
                    + firstNonBlank(problem.promptValue(), "unavailable")
                    + " / sealedEvidenceValue="
                    + firstNonBlank(problem.sealedEvidenceValue(), "unavailable");
            case "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING" -> "A required prompt evidence field was recorded as missing.";
            case "UNKNOWN_WITHOUT_REASON" -> "The field is unknown and no reason was recorded.";
            case "PROMPT_COMPACTED_SIGNAL" -> "The prompt was compacted or changed without complete field-level lineage.";
            case "PRODUCER_NOT_AVAILABLE" -> "The context producer did not provide the required field.";
            case "PROVISIONAL_EVIDENCE" -> "The field is provisional and must remain explicitly bounded.";
            case "NO_DIRECT_COMPARABLE" -> "No direct comparable history was recorded for the field.";
            case "BASELINE_MISMATCH_SIGNAL" -> "The field carries a baseline mismatch signal that requires explanation.";
            default -> firstNonBlank(problem.meaning(), "The actual prompt problem must be reviewed.");
        };
    }

    private boolean blockingPromptComparison(OfficialVerificationPromptComparison comparison) {
        if (comparison == null) {
            return false;
        }
        String state = safe(comparison.state()).toUpperCase(Locale.ROOT);
        if (state.startsWith("FINAL_PROMPT_")) {
            return true;
        }
        return switch (state) {
            case "PROMPT_MISSING",
                    "FACT_MISSING",
                    "VALUE_MISMATCH",
                    "CONTRACT_MISMATCH",
                    "REQUIRED_MISSING",
                    "CONDITIONAL_REQUIRED_MISSING",
                    "UNKNOWN_WITHOUT_REASON",
                    "PROMPT_COMPACTED_SIGNAL",
                    "PRODUCER_NOT_AVAILABLE",
                    "PROVISIONAL_EVIDENCE",
                    "NO_DIRECT_COMPARABLE",
                    "BASELINE_MISMATCH_SIGNAL" -> true;
            default -> false;
        };
    }

    private List<String> metricCodes(OfficialVerificationPromptComparison comparison) {
        Set<String> result = new LinkedHashSet<>();
        if (comparison != null && comparison.metricCodes() != null) {
            for (String metricCode : comparison.metricCodes()) {
                if (StringUtils.hasText(metricCode)) {
                    result.add(metricCode.trim().toUpperCase(Locale.ROOT));
                }
            }
        }
        return List.copyOf(result);
    }

    private String normalizedCode(String value) {
        return safe(value).toUpperCase(Locale.ROOT);
    }

    private String shortHash(String value) {
        String hash = sha256Hex(value == null ? "" : value);
        return hash.substring(0, Math.min(hash.length(), 16)).toUpperCase(Locale.ROOT);
    }

    private String actualPromptProblemId(String packageId, String aggregateRunId, String fieldKey, String state) {
        String seed = firstNonBlank(packageId, "") + "|"
                + firstNonBlank(fieldKey, "") + "|"
                + firstNonBlank(state, "");
        return "app-" + UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8));
    }

    private String actualPromptComparisonId(String packageId, String aggregateRunId, String fieldKey, String state) {
        String seed = firstNonBlank(packageId, "") + "|"
                + firstNonBlank(fieldKey, "") + "|"
                + firstNonBlank(state, "");
        return "apc-" + UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8));
    }

    private OfficialVerificationRunView runtimeMetricRunView(RuntimeEvidenceMetricResult metric, String requestId) {
        String runId = firstNonBlank(
                metric == null ? null : metric.officialRunId(),
                "actual-prompt-ledger-" + firstNonBlank(metric == null ? null : metric.metricCode(), "unknown"));
        return new RuntimeMetricRunView(metric, requestId, runId);
    }

    private record RuntimeMetricRunView(
            RuntimeEvidenceMetricResult metric,
            String requestId,
            String runId) implements OfficialVerificationRunView {

        @Override
        public String endpointKey() {
            return metric == null ? "" : metric.metricCode();
        }

        @Override
        public String endpointLabel() {
            return metric == null ? "" : metric.metricName();
        }

        @Override
        public int round() {
            return 1;
        }

        @Override
        public double score() {
            return metric == null ? 0.0d : metric.score();
        }

        @Override
        public int passedChecks() {
            return metric == null ? 0 : metric.passedChecks();
        }

        @Override
        public int totalChecks() {
            return metric == null ? 0 : metric.totalChecks();
        }

        @Override
        public Long processingTimeMs() {
            return null;
        }

        @Override
        public String state() {
            return metric == null ? "threshold_failed" : metric.state();
        }

        @Override
        public String stateTone() {
            return metric != null && "SUCCESS".equalsIgnoreCase(metric.state()) ? "success" : "danger";
        }

        @Override
        public String message() {
            return metric == null ? "" : metric.stateLabel();
        }

        @Override
        public String startedAt() {
            return null;
        }

        @Override
        public String completedAt() {
            return null;
        }

        @Override
        public List<? extends OfficialVerificationCheckResultView> checks() {
            return metric == null || metric.checks() == null
                    ? List.of()
                    : metric.checks().stream().map(RuntimeMetricCheckView::new).toList();
        }

        @Override
        public Map<String, String> requestFacts() {
            return Map.of();
        }

        @Override
        public Map<String, String> eventFacts() {
            return Map.of();
        }

        @Override
        public Map<String, String> promptFacts() {
            return Map.of();
        }

        @Override
        public Map<String, String> analysisFacts() {
            return Map.of();
        }

        @Override
        public List<? extends OfficialVerificationEventItemView> events() {
            return List.of();
        }

        @Override
        public Map<String, Object> rawEvidence() {
            Map<String, Object> raw = new LinkedHashMap<>();
            raw.put("source", "actualPromptProblemLedger");
            raw.put("metricCode", endpointKey());
            raw.put("runId", runId);
            return raw;
        }
    }

    private record RuntimeMetricCheckView(RuntimeEvidenceCheckResult check) implements OfficialVerificationCheckResultView {

        @Override
        public String checkCode() {
            return check == null ? "CHECK" : check.checkCode();
        }

        @Override
        public String label() {
            return check == null ? "" : check.label();
        }

        @Override
        public String expectedValue() {
            return check == null ? "" : check.expectedValue();
        }

        @Override
        public String actualValue() {
            return check == null ? "" : check.actualValue();
        }

        @Override
        public boolean pass() {
            return check != null && check.pass();
        }

        @Override
        public String source() {
            return check == null ? "" : check.source();
        }

        @Override
        public String severity() {
            return check == null ? "BLOCKING" : check.severity();
        }

        @Override
        public String failureType() {
            return check == null ? "MISSING_CHECK" : check.failureType();
        }

        @Override
        public String remediationOwner() {
            return check == null ? "" : check.remediationOwner();
        }

        @Override
        public String operatorReason() {
            return check == null ? "" : check.operatorReason();
        }

        @Override
        public String nextAction() {
            return check == null ? "" : check.nextAction();
        }

        @Override
        public String reverifyCriterion() {
            return check == null ? "" : check.reverifyCriterion();
        }

        @Override
        public String issueKey() {
            return check == null ? "" : check.issueKey();
        }

        @Override
        public boolean customerVisible() {
            return check != null && check.customerVisible();
        }

        @Override
        public String readinessScope() {
            return check == null ? "INTERNAL_EXECUTION_GATE" : check.readinessScope();
        }

        @Override
        public String purposeVersion() {
            return check == null ? "" : check.purposeVersion();
        }

        @Override
        public String inputReadinessState() {
            return check == null ? "NOT_READY" : check.inputReadinessState();
        }

        @Override
        public String purposeResult() {
            return check == null ? "ENGINE_CONTRACT_ERROR" : check.purposeResult();
        }

        @Override
        public String detectedSignalsJson() {
            return check == null ? "[]" : check.detectedSignalsJson();
        }

        @Override
        public String interpretationLinksJson() {
            return check == null ? "[]" : check.interpretationLinksJson();
        }

        @Override
        public String decisionUtility() {
            return check == null ? "" : check.decisionUtility();
        }

        @Override
        public String whyItMatters() {
            return check == null ? "" : check.whyItMatters();
        }
    }

    private void recordOperatorSnapshot(
            String aggregateRunId,
            SealedEvidencePackage pkg,
            String requestPath,
            String resourceId,
            String method,
            String promptHash,
            String contextHash,
            String certificateId,
            String caseId,
            List<PromptQualityIssue> issues,
            List<RuntimeEvidenceMetricResult> metrics,
            List<OfficialVerificationPromptComparison> promptComparisons) {
        if (operatorSnapshotService == null) {
            return;
        }
        operatorSnapshotService.record(
                aggregateRunId,
                pkg,
                requestPath,
                resourceId,
                method,
                promptHash,
                contextHash,
                certificateId,
                caseId,
                issues,
                metrics,
                promptComparisons);
    }

    private List<String> merge(List<String> left, List<String> right) {
        List<String> merged = new ArrayList<>();
        if (left != null) {
            merged.addAll(left);
        }
        if (right != null) {
            merged.addAll(right);
        }
        return merged.stream().filter(StringUtils::hasText).map(String::trim).distinct().toList();
    }

    private List<String> customerVisibleRuntimeSentences(List<String> values, boolean blockingFinding) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return values.stream()
                .filter(StringUtils::hasText)
                .map(value -> customerVisibleRuntimeSentence(value, blockingFinding))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private List<String> actualPromptProblemFindings(List<OfficialActualPromptProblem> problems) {
        if (problems == null || problems.isEmpty()) {
            return List.of();
        }
        return customerVisibleRuntimeSentences(problems.stream()
                .filter(problem -> problem != null && "BLOCKING".equalsIgnoreCase(firstNonBlank(problem.severity(), "")))
                .map(problem -> {
                    String title = firstNonBlank(problem.promptLabel(), "프롬프트 문제가 발견되었습니다.");
                    String reason = firstNonBlank(problem.whyItMatters(), problem.actualState(), problem.problemType());
                    return StringUtils.hasText(reason) ? title + ". " + reason : title;
                })
                .toList(), true);
    }

    private List<String> actualPromptProblemNextActions(List<OfficialActualPromptProblem> problems) {
        if (problems == null || problems.isEmpty()) {
            return List.of();
        }
        return customerVisibleRuntimeSentences(problems.stream()
                .filter(problem -> problem != null && "BLOCKING".equalsIgnoreCase(firstNonBlank(problem.severity(), "")))
                .map(problem -> firstNonBlank(problem.fixAction(), problem.reverifyCriterionDetail()))
                .filter(StringUtils::hasText)
                .toList(), false);
    }

    private int actualPromptProblemMetricCount(List<OfficialActualPromptProblem> problems) {
        if (problems == null || problems.isEmpty()) {
            return 0;
        }
        return (int) problems.stream()
                .filter(problem -> problem != null
                        && "BLOCKING".equalsIgnoreCase(firstNonBlank(problem.severity(), "")))
                .flatMap(problem -> problem.metricCodes().stream())
                .filter(StringUtils::hasText)
                .map(this::normalizedCode)
                .filter(metricCode -> !internalGateMetric(metricCode))
                .distinct()
                .count();
    }

    private String customerVisibleRuntimeSentence(String value, boolean blockingFinding) {
        String candidate = value == null ? "" : value.trim();
        if (PromptQualityCustomerSentencePolicy.isCustomerSentence(candidate)) {
            return candidate;
        }
        String metricName = customerMetricName(candidate);
        String sanitized = blockingFinding
                ? metricName + "에서 공식 기준을 충족하지 못한 항목이 발견되었습니다. 문제 해결 화면에서 실패 기준, 확인값, 담당 공정을 확인하십시오."
                : metricName + "의 실패 기준을 확인하고 담당 데이터 생산자 또는 프롬프트 조립 경로를 보강한 뒤 같은 증거 흐름으로 다시 검사하십시오.";
        return PromptQualityCustomerSentencePolicy.requireCustomerSentence(
                blockingFinding ? "runtime.blockingFinding" : "runtime.nextAction",
                sanitized);
    }

    private String customerMetricName(String value) {
        if (!StringUtils.hasText(value)) {
            return "official inspection metric";
        }
        for (OfficialVerificationMetricDefinition metric : metricCatalog.promptQualityMetrics()) {
            if (containsMetricCode(value, metric.code())) {
                return narrativeCatalog.metricName(metric.code());
            }
        }
        if (value.toLowerCase(Locale.ROOT).contains("prompt")) {
            return "증거와 프롬프트 일치성";
        }
        if (value.contains("@Protectable") || value.toLowerCase(Locale.ROOT).contains("protectable")) {
            return "보호 리소스 적격성";
        }
        return "공식 검사 지표";
    }

    private boolean containsMetricCode(String value, String metricCode) {
        if (!StringUtils.hasText(value) || !StringUtils.hasText(metricCode)) {
            return false;
        }
        return Pattern.compile("\\b" + Pattern.quote(metricCode.trim()) + "\\b", Pattern.CASE_INSENSITIVE)
                .matcher(value)
                .find();
    }

    private String groupName(String category) {
        return switch (safe(category)) {
            case "IMPLEMENTATION_ALIGNMENT" -> message("enterprise.pqa.runtimeVerification.metric.group.implementationAlignment", "Implementation alignment");
            case "RAG_AND_BASELINE" -> message("enterprise.pqa.runtimeVerification.metric.group.ragAndBaseline", "Learning and baseline");
            case "BEHAVIORAL_CONTEXT" -> message("enterprise.pqa.runtimeVerification.metric.group.behavioralContext", "Behavior context");
            case "LLM_DECISION" -> message("enterprise.pqa.runtimeVerification.metric.group.llmDecision", "Decision reliability");
            case "RESOURCE_ELIGIBILITY" -> message("enterprise.pqa.runtimeVerification.metric.group.resourceEligibility", "Operational promotion eligibility");
            default -> message("enterprise.pqa.runtimeVerification.metric.group.other", "Other");
        };
    }

    private void assertPromptConsistencyReady(RuntimeEvidencePromptConsistencyResult promptConsistency) {
        if (promptConsistency != null && !promptConsistency.blocking()) {
            return;
        }
        String reason = promptConsistency == null
                ? null
                : (promptConsistency.findings() == null ? List.<String>of() : promptConsistency.findings()).stream()
                .filter(StringUtils::hasText)
                .findFirst()
                .orElse(null);
        String base = message(
                "enterprise.pqa.runtimeVerification.error.promptConsistencyBlocked",
                "Official inspection cannot run because hard evidence integrity or prompt traceability checks failed.");
        throw new IllegalArgumentException(StringUtils.hasText(reason) ? base + " " + reason : base);
    }

    private void assertOfficialVerificationProcessReady(PromptQualityProcessScope scope) {
        List<String> previous = new ArrayList<>();
        for (var step : processRunService.steps(scope)) {
            if (PromptQualityProcessCodes.OFFICIAL_VERIFICATION.equals(step.stepCode())) {
                String state = step.executionState() == null ? "" : step.executionState().trim().toUpperCase(Locale.ROOT);
                if (PromptQualityProcessCodes.RUNNING.equals(state)
                        || PromptQualityProcessCodes.COMPLETED.equals(state)
                        || PromptQualityProcessCodes.FAILED.equals(state)) {
                    return;
                }
                break;
            }
            if (!PromptQualityProcessCodes.COMPLETED.equalsIgnoreCase(step.executionState())) {
                previous.add(step.stepCode());
            }
        }
        if (!previous.isEmpty()) {
            throw new IllegalStateException(message(
                    "enterprise.pqa.runtimeVerification.error.processSequenceBlocked",
                    "Official inspection cannot run because previous process stage is not completed: {0}.",
                    previous.get(0)));
        }
    }

    protected String message(String key, String fallback, Object... args) {
        if (messageResolver == null) {
            return args == null || args.length == 0 ? fallback : MessageFormat.format(fallback, args);
        }
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            return args == null || args.length == 0 ? fallback : MessageFormat.format(fallback, args);
        }
        return resolved;
    }

    private boolean officialRunPassed(OfficialVerificationRunView run) {
        if (run == null) {
            return false;
        }
        String normalized = run.state() == null ? "" : run.state().trim().toUpperCase(Locale.ROOT);
        return PASS_STATES.contains(normalized) || normalized.contains("THRESHOLD PASSED");
    }

    private boolean metricPassed(RuntimeEvidenceMetricResult metric) {
        if (metric == null) {
            return false;
        }
        String normalized = metric.state() == null ? "" : metric.state().trim().toUpperCase(Locale.ROOT);
        return PASS_STATES.contains(normalized) || normalized.contains("THRESHOLD PASSED");
    }

    private boolean customerBlockingMetric(RuntimeEvidenceMetricResult metric) {
        if (metric == null || internalGateMetric(metric.metricCode())) {
            return false;
        }
        if (metric.checks() == null || metric.checks().isEmpty()) {
            return !metricPassed(metric);
        }
        return metric.checks().stream()
                .anyMatch(check -> customerPromptQualityCheck(check)
                        && !check.pass()
                        && !runtimeInputReadinessNotReady(check)
                        && "BLOCKING".equalsIgnoreCase(firstNonBlank(check.severity(), "")));
    }

    private boolean runtimeInputReadinessNotReady(RuntimeEvidenceCheckResult check) {
        if (check == null) {
            return false;
        }
        String readiness = safe(check.inputReadinessState()).toUpperCase(Locale.ROOT);
        String purpose = safe(check.purposeResult()).toUpperCase(Locale.ROOT);
        String failure = safe(check.failureType()).toUpperCase(Locale.ROOT);
        return "NOT_READY".equals(readiness)
                || "INPUT_NOT_READY".equals(readiness)
                || "NOT_EVALUATED_INPUT_NOT_READY".equals(purpose)
                || "INPUT_NOT_READY".equals(purpose)
                || "INPUT_NOT_READY".equals(failure);
    }

    private boolean customerPromptQualityCheck(RuntimeEvidenceCheckResult check) {
        if (check == null || !check.customerVisible()) {
            return false;
        }
        return "CUSTOMER_PROMPT_QUALITY".equalsIgnoreCase(firstNonBlank(
                check.readinessScope(),
                "CUSTOMER_PROMPT_QUALITY"));
    }

    private boolean customerPromptQualityCheck(OfficialVerificationCheckResultView check) {
        if (check == null || !check.customerVisible()) {
            return false;
        }
        return "CUSTOMER_PROMPT_QUALITY".equalsIgnoreCase(firstNonBlank(
                check.readinessScope(),
                "CUSTOMER_PROMPT_QUALITY"));
    }

    private String readinessScope(OfficialVerificationCheckResultView check) {
        if (check == null) {
            return "CUSTOMER_PROMPT_QUALITY";
        }
        return firstNonBlank(
                check.readinessScope(),
                check.customerVisible() ? "CUSTOMER_PROMPT_QUALITY" : "INTERNAL_EXECUTION_GATE");
    }

    private String now() {
        return LocalDateTime.now(KOREA_ZONE).format(FORMATTER);
    }
}
