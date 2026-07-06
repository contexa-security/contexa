package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceScope;
import io.contexa.contexaiam.admin.promptquality.official.process.NoopPromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessCodes;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessScope;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMissingKnowledgeSignal;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceSearchCriteria;
import io.contexa.contexaiam.admin.promptquality.official.application.support.AbstractPromptQualityRuntimeEvidenceSupport;
import io.contexa.contexaiam.admin.promptquality.official.state.NoopPromptQualityStateCatalog;
import io.contexa.contexaiam.admin.promptquality.official.state.PromptQualityStateCatalog;
import io.contexa.contexaiam.admin.promptquality.official.state.PromptQualityStateDescriptor;
import io.contexa.contexaiam.admin.promptquality.official.state.PromptQualityStateDimension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class DefaultPromptQualityRuntimeEvidenceService
        extends AbstractPromptQualityRuntimeEvidenceSupport
        implements PromptQualityRuntimeEvidenceService {

    private static final int MAX_PAGE_SIZE = 100;

    private final SealedEvidencePackageQueryService lookupService;
    private final RuntimeEvidencePromptConsistencyGate promptConsistencyGate;
    private final PromptQualityStateCatalog stateCatalog;
    private final PromptQualityProcessRunService processRunService;

    public DefaultPromptQualityRuntimeEvidenceService(
            SealedEvidencePackageQueryService lookupService,
            ObjectMapper objectMapper) {
        this(lookupService, objectMapper, null, null);
    }

    public DefaultPromptQualityRuntimeEvidenceService(
            SealedEvidencePackageQueryService lookupService,
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver) {
        this(lookupService, objectMapper, messageResolver, null);
    }

    public DefaultPromptQualityRuntimeEvidenceService(
            SealedEvidencePackageQueryService lookupService,
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate) {
        this(lookupService, objectMapper, messageResolver, promptConsistencyGate,
                new NoopPromptQualityStateCatalog(), new NoopPromptQualityProcessRunService());
    }

    public DefaultPromptQualityRuntimeEvidenceService(
            SealedEvidencePackageQueryService lookupService,
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            PromptQualityStateCatalog stateCatalog) {
        this(lookupService, objectMapper, messageResolver, promptConsistencyGate, stateCatalog,
                new NoopPromptQualityProcessRunService());
    }

    public DefaultPromptQualityRuntimeEvidenceService(
            SealedEvidencePackageQueryService lookupService,
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            PromptQualityStateCatalog stateCatalog,
            PromptQualityProcessRunService processRunService) {
        super(objectMapper, messageResolver);
        this.lookupService = lookupService;
        this.promptConsistencyGate = promptConsistencyGate == null
                ? new DefaultRuntimeEvidencePromptConsistencyGate(objectMapper, null, messageResolver)
                : promptConsistencyGate;
        this.stateCatalog = stateCatalog == null ? new NoopPromptQualityStateCatalog() : stateCatalog;
        this.processRunService = processRunService == null ? new NoopPromptQualityProcessRunService() : processRunService;
    }

    @Override
    public List<RuntimeEvidencePackageSummary> search(RuntimeEvidenceSearchCriteria criteria) {
        RuntimeEvidenceSearchCriteria safeCriteria = criteria == null
                ? new RuntimeEvidenceSearchCriteria(null, null, null, null, null, null, null, null, 0, 20)
                : criteria;
        if (StringUtils.hasText(safeCriteria.packageId())) {
            return lookupService.findByPackageId(safeCriteria.packageId().trim())
                    .filter(pkg -> matches(pkg, safeCriteria))
                    .map(pkg -> List.of(toSummary(pkg)))
                    .orElse(List.of());
        }
        Instant to = safeCriteria.to() == null ? Instant.now() : safeCriteria.to();
        Instant from = safeCriteria.from() == null ? to.minus(7, ChronoUnit.DAYS) : safeCriteria.from();
        PageRequest pageable = PageRequest.of(
                Math.max(0, safeCriteria.page()),
                Math.max(1, Math.min(MAX_PAGE_SIZE, safeCriteria.size() <= 0 ? 20 : safeCriteria.size())));

        Page<SealedEvidencePackage> page;
        if (StringUtils.hasText(safeCriteria.userId())) {
            page = lookupService.searchByUserId(safeCriteria.userId().trim(), from, to, pageable);
        }
        else if (StringUtils.hasText(safeCriteria.tenantId())) {
            page = lookupService.searchByTenantId(safeCriteria.tenantId().trim(), from, to, pageable);
        }
        else {
            page = lookupService.searchRecent(from, to, pageable);
        }
        return page.getContent().stream()
                .filter(pkg -> matches(pkg, safeCriteria))
                .map(this::toSummary)
                .toList();
    }

    @Override
    public RuntimeEvidencePackageDetail findDetail(String packageId) {
        SealedEvidencePackage pkg = lookupService.findByPackageId(packageId)
                .orElseThrow(() -> new IllegalArgumentException(message(
                        "enterprise.pqa.runtimeVerification.error.packageId.notFound",
                        "Request evidence packageId was not found: {0}",
                        packageId)));
        Map<String, Object> requestFacts = parseJson(pkg.getRequestFactsJson());
        Map<String, Object> authState = parseJson(pkg.getAuthStateJson());
        Map<String, Object> promptMetadata = Map.of();
        Map<String, Object> decision = parseJson(pkg.getDecisionJson());
        Map<String, Object> baselineSnapshot = parseJson(pkg.getBaselineSnapshotJson());
        Map<String, Object> ragResults = parseJson(pkg.getRagResultsJson());
        List<RuntimeEvidenceMissingKnowledgeSignal> missingSignalDetails = missingKnowledgeSignalDetails(pkg);
        List<String> missingSignals = missingSignalDetails.stream()
                .map(RuntimeEvidenceMissingKnowledgeSignal::title)
                .toList();
        boolean integrityValid = lookupService.verifyIntegrity(pkg);
        return new RuntimeEvidencePackageDetail(
                toSummary(pkg, integrityValid),
                hasText(pkg.getRawSystemPrompt()),
                hasText(pkg.getRawUserPrompt()),
                hasText(pkg.getSystemPromptText()),
                hasText(pkg.getUserPromptText()),
                hasText(pkg.getBaselineSnapshotJson()),
                hasText(pkg.getRagResultsJson()),
                promptPreview(pkg.getSystemPromptText()),
                promptPreview(pkg.getUserPromptText()),
                requestFacts,
                authState,
                promptMetadata,
                decision,
                baselineSnapshot,
                ragResults,
                missingSignals,
                missingSignalDetails,
                qualityWarnings(pkg, integrityValid),
                promptConsistencyGate.evaluate(pkg),
                pkg.getSystemPromptText(),
                pkg.getUserPromptText());
    }

    private boolean matches(SealedEvidencePackage pkg, RuntimeEvidenceSearchCriteria criteria) {
        Map<String, Object> requestFacts = parseJson(pkg.getRequestFactsJson());
        Map<String, Object> promptMetadata = Map.of();
        String actualPath = requestPath(pkg, requestFacts);
        boolean pathMatched = matchesPath(criteria.resourceUrl(), actualPath);
        return matchesText(criteria.tenantId(), pkg.getTenantId())
                && matchesText(criteria.userId(), pkg.getUserId())
                && pathMatched
                && matchesResource(
                criteria.resourceId(),
                resourceId(pkg, requestFacts, promptMetadata),
                criteria.resourceUrl(),
                actualPath,
                pathMatched)
                && matchesText(criteria.httpMethod(), httpMethod(requestFacts));
    }

    private boolean matchesText(String expected, String actual) {
        return !StringUtils.hasText(expected)
                || (StringUtils.hasText(actual) && actual.trim().equalsIgnoreCase(expected.trim()));
    }

    private boolean matchesPath(String expected, String actual) {
        return !StringUtils.hasText(expected)
                || (StringUtils.hasText(actual)
                && (normalizePath(actual).equalsIgnoreCase(normalizePath(expected))
                || templateMatches(normalizePath(expected), normalizePath(actual))));
    }

    private boolean matchesResource(
            String expected,
            String actual,
            String expectedPath,
            String actualPath,
            boolean pathMatched) {
        if (!StringUtils.hasText(expected)) {
            return true;
        }
        if (StringUtils.hasText(actual)
                && (actual.trim().equalsIgnoreCase(expected.trim())
                || templateMatches(expected.trim(), actual.trim()))) {
            return true;
        }
        if (!pathMatched || !StringUtils.hasText(expectedPath) || !StringUtils.hasText(actualPath)) {
            return false;
        }
        String extractedResourceId = extractTemplateVariable(
                normalizePath(expectedPath),
                normalizePath(actualPath),
                "resourceId");
        if (!StringUtils.hasText(extractedResourceId)) {
            return false;
        }
        if (StringUtils.hasText(actual) && actual.trim().equalsIgnoreCase(extractedResourceId.trim())) {
            return true;
        }
        return false;
    }

    private boolean templateMatches(String template, String actual) {
        if (!StringUtils.hasText(template) || !StringUtils.hasText(actual) || !template.contains("{")) {
            return false;
        }
        StringBuilder regex = new StringBuilder("^");
        for (int index = 0; index < template.length(); index++) {
            char current = template.charAt(index);
            if (current == '{') {
                int end = template.indexOf('}', index);
                if (end > index) {
                    regex.append("[^/]+");
                    index = end;
                    continue;
                }
            }
            regex.append(Pattern.quote(String.valueOf(current)));
        }
        regex.append("$");
        return Pattern.compile(regex.toString(), Pattern.CASE_INSENSITIVE)
                .matcher(actual)
                .matches();
    }

    private String extractTemplateVariable(String template, String actual, String variableName) {
        if (!StringUtils.hasText(template)
                || !StringUtils.hasText(actual)
                || !StringUtils.hasText(variableName)
                || !template.contains("{" + variableName + "}")) {
            return null;
        }
        String[] templateParts = template.split("/");
        String[] actualParts = actual.split("/");
        if (templateParts.length != actualParts.length) {
            return null;
        }
        String token = "{" + variableName + "}";
        for (int index = 0; index < templateParts.length; index++) {
            String templatePart = templateParts[index];
            if (templatePart.equals(token)) {
                return actualParts[index];
            }
        }
        return null;
    }

    private RuntimeEvidencePackageSummary toSummary(SealedEvidencePackage pkg) {
        return toSummary(pkg, lookupService.verifyIntegrity(pkg));
    }

    private RuntimeEvidencePackageSummary toSummary(SealedEvidencePackage pkg, boolean integrityValid) {
        Map<String, Object> requestFacts = parseJson(pkg.getRequestFactsJson());
        Map<String, Object> promptMetadata = Map.of();
        Map<String, Object> decision = parseJson(pkg.getDecisionJson());
        PromptQualityStateDescriptor state = stateCatalog.runtimeEvidence(
                pkg.isSealed(),
                integrityValid,
                false);
        String path = requestPath(pkg, requestFacts);
        String resourceId = resourceId(pkg, requestFacts, promptMetadata);
        String method = httpMethod(requestFacts);
        return new RuntimeEvidencePackageSummary(
                pkg.getPackageId(),
                pkg.getCorrelationId(),
                pkg.getTenantId(),
                pkg.getUserId(),
                pkg.getCapturedAt(),
                path,
                resourceId,
                method,
                decisionAction(decision),
                decisionConfidence(decision),
                pkg.isSealed(),
                integrityValid,
                pkg.getPromptHash(),
                promptTextLength(pkg),
                state.label(),
                state.nextAction(),
                state.code(),
                state);
    }

    private List<String> qualityWarnings(SealedEvidencePackage pkg, boolean integrityValid) {
        return Stream.of(
                        hasText(pkg.getRawSystemPrompt()) ? null : message("enterprise.pqa.runtimeEvidence.warning.rawSystemPromptMissing", "Raw system prompt is not stored."),
                        hasText(pkg.getRawUserPrompt()) ? null : message("enterprise.pqa.runtimeEvidence.warning.rawUserPromptMissing", "Raw user prompt is not stored."),
                        hasText(pkg.getSystemPromptText()) ? null : message("enterprise.pqa.runtimeEvidence.warning.llmSystemPromptMissing", "System prompt sent to the LLM is missing."),
                        hasText(pkg.getUserPromptText()) ? null : message("enterprise.pqa.runtimeEvidence.warning.llmUserPromptMissing", "User prompt sent to the LLM is missing."),
                        integrityValid ? null : message("enterprise.pqa.runtimeEvidence.warning.integrityMismatch", "Evidence hash does not match."))
                .filter(StringUtils::hasText)
                .toList();
    }
}
