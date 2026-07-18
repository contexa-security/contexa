package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.adjudication.ScorecardResult;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePromptEvidenceBackfill;
import io.contexa.contexacore.verification.metric.OfficialContextHashStateResolver;
import io.contexa.contexacore.verification.replay.DeterministicReplayResult;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptPreflightService;
import io.contexa.contexaiam.admin.promptquality.official.application.support.AbstractPromptQualityRuntimeEvidenceSupport;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceScope;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRequest;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;

public final class OfficialVerificationEvidencePreflight extends AbstractPromptQualityRuntimeEvidenceSupport {

    private static final Logger log = LoggerFactory.getLogger(OfficialVerificationEvidencePreflight.class);
    private static final DateTimeFormatter GENERATED_AT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final ZoneId KOREA_ZONE = ZoneId.of("Asia/Seoul");

    private final SealedEvidencePackageQueryService lookupService;
    private final RuntimeEvidenceReplayService replayService;
    private final RuntimeEvidencePromptScorecardService promptScorecardService;
    private final RuntimeEvidencePromptConsistencyGate promptConsistencyGate;
    private final OfficialVerificationResourceResolver resourceResolver;
    private final FinalPromptPreflightService finalPromptPreflightService;

    public OfficialVerificationEvidencePreflight(
            SealedEvidencePackageQueryService lookupService,
            RuntimeEvidenceReplayService replayService,
            RuntimeEvidencePromptScorecardService promptScorecardService,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            OfficialVerificationResourceResolver resourceResolver,
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver) {
        super(objectMapper, messageResolver);
        this.lookupService = Objects.requireNonNull(lookupService, "lookupService");
        this.replayService = Objects.requireNonNull(replayService, "replayService");
        this.promptScorecardService = Objects.requireNonNull(promptScorecardService, "promptScorecardService");
        this.promptConsistencyGate = Objects.requireNonNull(promptConsistencyGate, "promptConsistencyGate");
        this.resourceResolver = Objects.requireNonNull(resourceResolver, "resourceResolver");
        this.finalPromptPreflightService = new FinalPromptPreflightService(objectMapper, messageResolver::resolveRequired);
    }

    public EvidenceContext load(RuntimeEvidenceVerificationRequest request) {
        if (request == null || !StringUtils.hasText(request.packageId())) {
            throw new IllegalArgumentException(message("enterprise.pqa.runtimeVerification.error.packageId.required"));
        }
        SealedEvidencePackage loaded = lookupService.findByPackageId(request.packageId().trim())
                .orElseThrow(() -> new NoSuchElementException(message(
                        "enterprise.pqa.runtimeVerification.error.packageId.notFound",
                        request.packageId())));
        SealedEvidencePackage evidencePackage = prepare(loaded);
        Map<String, Object> requestFacts = parseJson(evidencePackage.getRequestFactsJson());
        Map<String, Object> promptMetadata =
                parsePromptExecutionMetadataHeader(evidencePackage.getPromptExecutionMetadataJson());
        String requestPath = requestPath(evidencePackage, requestFacts);
        String resourceId = resourceId(evidencePackage, requestFacts, promptMetadata);
        String httpMethod = httpMethod(requestFacts);
        String actualResourceId = resourceResolver.actualResourceId(
                requestFacts, promptMetadata, requestPath, resourceId, evidencePackage);
        boolean integrityValid = lookupService.verifyIntegrity(evidencePackage);
        RuntimeEvidencePromptConsistencyResult promptConsistency = promptConsistencyGate.evaluate(evidencePackage);
        String operatorId = firstNonBlank(request.operatorId(), evidencePackage.getUserId(), "runtime-pqa");
        PromptQualityProcessScope processScope = new PromptQualityProcessScope(
                firstNonBlank(evidencePackage.getTenantId(), PromptQualityAssuranceScope.DEFAULT_TENANT_ID),
                requestPath,
                resourceId,
                httpMethod,
                PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION,
                PromptQualityAssuranceScope.DEFAULT_MODEL_PROFILE,
                PromptQualityAssuranceScope.DEFAULT_VERIFIER_VERSION);
        String requestId = firstNonBlank(
                text(requestFacts, "requestId"),
                text(promptMetadata, "requestId"),
                evidencePackage.getCorrelationId());
        String promptHash = firstNonBlank(
                evidencePackage.getPromptHash(), text(promptMetadata, "promptHash"));
        String contextHash = OfficialContextHashStateResolver.resolve(
                requestFacts,
                promptMetadata,
                evidencePackage.getCanonicalContextJson()).contextHash();
        return new EvidenceContext(
                evidencePackage,
                generatedAt(),
                requestFacts,
                promptMetadata,
                requestPath,
                resourceId,
                actualResourceId,
                httpMethod,
                integrityValid,
                promptConsistency,
                operatorId,
                processScope,
                requestId,
                promptHash,
                contextHash);
    }

    public Optional<SealedEvidencePackage> findByPackageId(String packageId) {
        return StringUtils.hasText(packageId)
                ? lookupService.findByPackageId(packageId.trim())
                : Optional.empty();
    }

    public String promptGovernanceVersion(Map<String, Object> promptMetadata) {
        Object governanceValue = promptMetadata == null ? null : promptMetadata.get("governanceDescriptor");
        Map<String, Object> governance = governanceValue instanceof Map<?, ?> value
                ? objectMapper.convertValue(value, new TypeReference<>() {})
                : Map.of();
        return firstNonBlank(
                text(promptMetadata, "promptVersion"),
                text(governance, "promptVersion"),
                text(governance, "contractVersion"));
    }

    public String resourceTemplateId(
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            ProtectableResourceDescriptor descriptor,
            String resourceId) {
        return resourceResolver.resourceTemplateId(requestFacts, promptMetadata, descriptor, resourceId);
    }
    public ProtectableResourceDescriptor resolveDescriptor(EvidenceContext context) {
        return resourceResolver.resolve(
                context.evidencePackage(),
                context.requestFacts(),
                context.promptMetadata(),
                context.requestPath(),
                context.resourceId(),
                context.httpMethod());
    }

    public String resourceTemplateId(EvidenceContext context, ProtectableResourceDescriptor descriptor) {
        return resourceResolver.resourceTemplateId(
                context.requestFacts(), context.promptMetadata(), descriptor, context.resourceId());
    }


    public void assertFinalPromptReady(SealedEvidencePackage evidencePackage) {
        assertSealedPromptEvidencePackage(evidencePackage);
        finalPromptPreflightService.assertReady(evidencePackage);
    }


    public ScorecardResult scorecard(SealedEvidencePackage evidencePackage) {
        try {
            return promptScorecardService.evaluate(evidencePackage);
        }
        catch (RuntimeException ignored) {
            return null;
        }
    }

    public DeterministicReplayResult replay(SealedEvidencePackage evidencePackage) {
        try {
            return replayService.replay(evidencePackage.getPackageId());
        }
        catch (RuntimeException exception) {
            return new DeterministicReplayResult(
                    evidencePackage.getPackageId(),
                    false,
                    evidencePackage.getPromptHash(),
                    null,
                    1,
                    0,
                    List.of(message(
                            "enterprise.pqa.runtimeVerification.replay.failedTpl",
                            exception.getMessage())),
                    List.of(),
                    List.of(),
                    Instant.now());
        }
    }

    private SealedEvidencePackage prepare(SealedEvidencePackage loaded) {
        SealedEvidencePromptEvidenceBackfill.Result result =
                SealedEvidencePromptEvidenceBackfill.prepare(objectMapper, loaded, messageResolver::resolveRequired);
        if (result.recovered()) {
            log.error(
                    "PQA sealed evidence prompt contract recovered for official verification. packageId={}, recoveredFields={}",
                    loaded == null ? null : loaded.getPackageId(),
                    result.recoveredFields());
        }
        if (!result.ready()) {
            throw new IllegalStateException(message(
                    "enterprise.pqa.runtimeVerification.preflight.inputContractInvalidWithRemediation",
                    String.join(" ", result.violations())));
        }
        return result.packageForVerification();
    }

    private void assertSealedPromptEvidencePackage(SealedEvidencePackage evidencePackage) {
        List<String> violations = new ArrayList<>();
        if (!evidencePackage.hasSealedState()) {
            violations.add(message(
                    "enterprise.pqa.runtimeVerification.preflight.sealStateInvalid",
                    evidencePackage.getSealState()));
        }
        requireText(
                violations,
                evidencePackage.getPromptEvidenceManifestJson(),
                message("enterprise.pqa.runtimeVerification.preflight.manifestMissing"));
        requireText(
                violations,
                evidencePackage.getSystemPromptHash(),
                message("enterprise.pqa.runtimeVerification.preflight.hashMissing", "systemPromptHash"));
        requireText(
                violations,
                evidencePackage.getUserPromptHash(),
                message("enterprise.pqa.runtimeVerification.preflight.hashMissing", "userPromptHash"));
        requireText(
                violations,
                evidencePackage.getRawSystemPromptHash(),
                message("enterprise.pqa.runtimeVerification.preflight.hashMissing", "rawSystemPromptHash"));
        requireText(
                violations,
                evidencePackage.getRawUserPromptHash(),
                message("enterprise.pqa.runtimeVerification.preflight.hashMissing", "rawUserPromptHash"));
        Map<String, Object> manifest = parseJson(evidencePackage.getPromptEvidenceManifestJson());
        if (!manifest.isEmpty() && !Boolean.TRUE.equals(manifest.get("sealable"))) {
            log.error(
                    "PQA sealed evidence prompt projection contract failed; official verification will continue and record the failed fields as findings. packageId={}, sealFailureReason={}",
                    evidencePackage.getPackageId(),
                    evidencePackage.getSealFailureReason());
        }
        if (!violations.isEmpty()) {
            throw new IllegalStateException(message(
                    "enterprise.pqa.runtimeVerification.preflight.inputContractInvalid",
                    String.join(" ", violations)));
        }
    }

    private void requireText(List<String> violations, String value, String violation) {
        if (!StringUtils.hasText(value)) {
            violations.add(violation);
        }
    }

    private String generatedAt() {
        return LocalDateTime.now(KOREA_ZONE).format(GENERATED_AT);
    }

    public record EvidenceContext(
            SealedEvidencePackage evidencePackage,
            String generatedAt,
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            String requestPath,
            String resourceId,
            String actualResourceId,
            String httpMethod,
            boolean integrityValid,
            RuntimeEvidencePromptConsistencyResult promptConsistency,
            String operatorId,
            PromptQualityProcessScope processScope,
            String requestId,
            String promptHash,
            String contextHash) {

        public PromptQualityAssuranceScope assuranceScope() {
            return new PromptQualityAssuranceScope(
                    processScope.tenantId(),
                    processScope.resourceUrl(),
                    processScope.resourceId(),
                    processScope.httpMethod(),
                    processScope.promptContractVersion(),
                    processScope.modelProfile(),
                    processScope.verifierVersion());
        }
    }
}