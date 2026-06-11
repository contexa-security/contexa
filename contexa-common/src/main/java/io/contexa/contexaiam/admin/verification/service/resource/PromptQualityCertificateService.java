package io.contexa.contexaiam.admin.verification.service.resource;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.repository.PromptQualityCertificateLedgerRepository;
import io.contexa.contexacore.repository.PromptQualityIssueCaseRepository;
import io.contexa.contexacore.repository.ProtectableResourceRegistryRepository;
import io.contexa.contexacore.saas.domain.entity.PromptQualityCertificateLedgerRecord;
import io.contexa.contexacore.saas.domain.entity.PromptQualityIssueCaseRecord;
import io.contexa.contexacore.saas.domain.entity.ProtectableResourceRegistryRecord;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricCatalog;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.verification.service.resource.ProtectableResourceCatalogService.ProtectableResourceDescriptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HexFormat;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class PromptQualityCertificateService {

    private static final int RECENT_CERTIFICATE_LIMIT = 100;
    private static final int CERTIFICATE_VALID_DAYS = 30;
    private static final ZoneId KOREA_ZONE = ZoneId.of("Asia/Seoul");
    private static final String DEFAULT_TENANT_ID = "default";
    private static final String DEFAULT_PROMPT_CONTRACT_VERSION = "official-prompt-contract-v1";
    private static final String DEFAULT_MODEL_PROFILE = "default-model-profile";
    private static final String DEFAULT_VERIFIER_VERSION = "official-verifier-v1";
    private static final String EVIDENCE_SOURCE_SEALED_RUNTIME_PACKAGE = "SEALED_RUNTIME_PACKAGE";
    private static final String EVIDENCE_SOURCE_OFFICIAL_VERIFICATION_RUN = "OFFICIAL_VERIFICATION_RUN";
    private static final String EVIDENCE_SOURCE_UNKNOWN = "UNKNOWN";
    private static final String REQUEST_LATEST_CERTIFICATE_CACHE =
            PromptQualityCertificateService.class.getName() + ".latestByScopeHash";

    private final OfficialVerificationMetricCatalog metricCatalog;
    private final PromptQualityCertificateLedgerRepository ledgerRepository;
    private final ProtectableResourceRegistryRepository registryRepository;
    private final PromptQualityIssueCaseRepository issueCaseRepository;
    private final PromptQualityCertificateAuditService auditService;
    private final PromptQualityCertificateStateMachine stateMachine;
    private final ObjectMapper objectMapper;
    private final Map<String, PromptQualityCertificate> latestByScopeHash = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<PromptQualityCertificate> recentCertificates = new CopyOnWriteArrayList<>();

    public PromptQualityCertificateService(OfficialVerificationMetricCatalog metricCatalog) {
        this(
                metricCatalog,
                (PromptQualityCertificateLedgerRepository) null,
                (ProtectableResourceRegistryRepository) null,
                (PromptQualityIssueCaseRepository) null,
                null,
                new PromptQualityCertificateStateMachine(),
                new ObjectMapper()
        );
    }

    @Autowired
    public PromptQualityCertificateService(
            OfficialVerificationMetricCatalog metricCatalog,
            ObjectProvider<PromptQualityCertificateLedgerRepository> ledgerRepositoryProvider,
            ObjectProvider<ProtectableResourceRegistryRepository> registryRepositoryProvider,
            ObjectProvider<PromptQualityIssueCaseRepository> issueCaseRepositoryProvider,
            ObjectProvider<PromptQualityCertificateAuditService> auditServiceProvider,
            ObjectProvider<PromptQualityCertificateStateMachine> stateMachineProvider,
            ObjectMapper objectMapper
    ) {
        this(
                metricCatalog,
                ledgerRepositoryProvider != null ? ledgerRepositoryProvider.getIfAvailable() : null,
                registryRepositoryProvider != null ? registryRepositoryProvider.getIfAvailable() : null,
                issueCaseRepositoryProvider != null ? issueCaseRepositoryProvider.getIfAvailable() : null,
                auditServiceProvider != null ? auditServiceProvider.getIfAvailable() : null,
                stateMachineProvider != null ? stateMachineProvider.getIfAvailable() : new PromptQualityCertificateStateMachine(),
                objectMapper
        );
    }

    public PromptQualityCertificateService(
            OfficialVerificationMetricCatalog metricCatalog,
            PromptQualityCertificateLedgerRepository ledgerRepository,
            ObjectMapper objectMapper
    ) {
        this(metricCatalog, ledgerRepository, null, null, null, new PromptQualityCertificateStateMachine(), objectMapper);
    }

    public PromptQualityCertificateService(
            OfficialVerificationMetricCatalog metricCatalog,
            PromptQualityCertificateLedgerRepository ledgerRepository,
            ProtectableResourceRegistryRepository registryRepository,
            ObjectMapper objectMapper
    ) {
        this(metricCatalog, ledgerRepository, registryRepository, null, null, new PromptQualityCertificateStateMachine(), objectMapper);
    }

    public PromptQualityCertificateService(
            OfficialVerificationMetricCatalog metricCatalog,
            PromptQualityCertificateLedgerRepository ledgerRepository,
            ProtectableResourceRegistryRepository registryRepository,
            PromptQualityIssueCaseRepository issueCaseRepository,
            PromptQualityCertificateAuditService auditService,
            PromptQualityCertificateStateMachine stateMachine,
            ObjectMapper objectMapper
    ) {
        this.metricCatalog = metricCatalog;
        this.ledgerRepository = ledgerRepository;
        this.registryRepository = registryRepository;
        this.issueCaseRepository = issueCaseRepository;
        this.auditService = auditService;
        this.stateMachine = stateMachine != null ? stateMachine : new PromptQualityCertificateStateMachine();
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public PromptQualityCertificate issue(
            String generatedAt,
            String userId,
            String resourceUrl,
            String resourceId,
            String httpMethod,
            ProtectableResourceDescriptor descriptor,
            List<MetricRunEvidence> evidence,
            List<MetricExecutionFailure> failures
    ) {
        CertificateScope scope = CertificateScope.of(
                DEFAULT_TENANT_ID,
                resourceUrl,
                httpMethod,
                resourceId,
                DEFAULT_PROMPT_CONTRACT_VERSION,
                DEFAULT_MODEL_PROFILE,
                DEFAULT_VERIFIER_VERSION
        );
        return issue(generatedAt, userId, scope, descriptor, evidence, failures);
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public PromptQualityCertificate issue(
            String generatedAt,
            String userId,
            CertificateScope scope,
            ProtectableResourceDescriptor descriptor,
            List<MetricRunEvidence> evidence,
            List<MetricExecutionFailure> failures
    ) {
        String resourceUrl = scope.resourceUrl();
        Map<String, MetricRunEvidence> evidenceByMetric = new LinkedHashMap<>();
        if (evidence != null) {
            evidence.forEach(item -> evidenceByMetric.put(normalizeMetricCode(item.metricCode()), item));
        }

        List<MetricCertificateItem> metricItems = metricCatalog.promptQualityMetrics().stream()
                .map(metric -> metricItem(metric, evidenceByMetric.get(normalizeMetricCode(metric.code())), failures))
                .toList();

        int total = metricItems.size();
        int verified = (int) metricItems.stream().filter(MetricCertificateItem::verified).count();
        int failed = (int) metricItems.stream().filter(item -> "FAILED".equals(item.state())).count();
        int missing = (int) metricItems.stream().filter(item -> "MISSING".equals(item.state())).count();
        boolean protectablePresent = descriptor != null;
        boolean verificationRequired = descriptor == null || descriptor.verificationRequired();
        boolean issued = protectablePresent && verificationRequired && total > 0 && verified == total;
        PromptQualityCertificateState certificateState = issued
                ? PromptQualityCertificateState.ISSUED
                : PromptQualityCertificateState.BLOCKED;
        ProtectableResourceOperationalState operationalState = issued
                ? ProtectableResourceOperationalState.CERTIFIED
                : ProtectableResourceOperationalState.BLOCKED;
        String state = certificateState.name();
        String stateLabel = certificateState.label();
        String zeroTrustState = operationalState.name();
        String zeroTrustStateLabel = operationalState.label();

        List<String> blockingFindings = blockingFindings(protectablePresent, verificationRequired, metricItems, failures);
        List<String> recommendedActions = recommendedActions(protectablePresent, verificationRequired, metricItems, failures);
        SixWReport sixW = PromptQualityCertificateNarrative.sixW(generatedAt, resourceUrl, userId, issued);

        String certificateId = "pqc-" + UUID.randomUUID();
        String requestContextHash = evidenceHash(evidence, "request-context");
        String learningContextHash = evidenceHash(evidence, "learning-context");
        String systemPromptHash = evidenceHash(evidence, "system-prompt");
        String userPromptHash = evidenceHash(evidence, "user-prompt");
        String promptHash = sha256(String.join("|", systemPromptHash, userPromptHash));
        String contextHash = sha256(String.join("|", requestContextHash, learningContextHash));
        RuntimeEvidenceSource runtimeSource = runtimeEvidenceSource(evidence);
        PromptQualityIssueCase issueCase = issueCase(certificateId, scope, state, blockingFindings, recommendedActions, generatedAt, evidence);
        EvidenceLineage evidenceLineage = evidenceLineage(certificateId, scope, evidence, metricItems, requestContextHash, learningContextHash, systemPromptHash, userPromptHash);
        RemediationLoop remediationLoop = remediationLoop(state, blockingFindings, recommendedActions);

        PromptQualityCertificate certificate = new PromptQualityCertificate(
                certificateId,
                scope,
                state,
                stateLabel,
                issued,
                zeroTrustState,
                zeroTrustStateLabel,
                operationalState.name(),
                operationalState.label(),
                issued ? valueOrDefault(generatedAt, null) : null,
                issued ? LocalDateTime.now(KOREA_ZONE).plusDays(CERTIFICATE_VALID_DAYS).toString() : null,
                null,
                null,
                null,
                runtimeSource.sealedEvidencePackageId(),
                runtimeSource.evidenceSourceType(),
                runtimeSource.runtimePromptHash(),
                runtimeSource.runtimeSystemPromptHash(),
                runtimeSource.runtimeUserPromptHash(),
                runtimeSource.runtimeDecisionHash(),
                promptHash,
                systemPromptHash,
                userPromptHash,
                contextHash,
                evidenceRequestIds(evidence),
                runIds(metricItems),
                valueOrDefault(scope.resourceUrl(), "n/a"),
                valueOrDefault(scope.protectableResourceId(), "n/a"),
                valueOrDefault(scope.httpMethod(), "GET").toUpperCase(Locale.ROOT),
                descriptor != null ? descriptor.methodIdentifier() : null,
                descriptor != null ? descriptor.criticality() : null,
                descriptor != null && descriptor.verificationRequired(),
                total,
                verified,
                failed,
                missing,
                blockingFindings,
                PromptQualityCertificateNarrative.certificateSummary(issued),
                sixW,
                issueCase,
                evidenceLineage,
                remediationLoop,
                metricItems,
                recommendedActions
        );

        remember(certificate);
        persist(certificate);
        return certificate;
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<PromptQualityCertificate> recentCertificates() {
        if (ledgerRepository != null) {
            List<PromptQualityCertificate> persisted = ledgerRepository.findTop100ByOrderByRecordedAtDesc().stream()
                    .map(this::fromRecord)
                    .toList();
            if (!persisted.isEmpty()) {
                return persisted;
            }
        }
        return recentCertificates.stream()
                .limit(RECENT_CERTIFICATE_LIMIT)
                .toList();
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PromptQualityCertificate latestFor(String resourceUrl, String resourceId) {
        return latestFor(resourceUrl, resourceId, "GET");
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PromptQualityCertificate latestFor(String resourceUrl, String resourceId, String httpMethod) {
        CertificateScope scope = CertificateScope.of(
                DEFAULT_TENANT_ID,
                resourceUrl,
                httpMethod,
                resourceId,
                DEFAULT_PROMPT_CONTRACT_VERSION,
                DEFAULT_MODEL_PROFILE,
                DEFAULT_VERIFIER_VERSION
        );
        return latestFor(scope);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Map<CertificateScope, PromptQualityCertificate> latestForAll(List<CertificateScope> scopes) {
        if (scopes == null || scopes.isEmpty()) {
            return Map.of();
        }
        Map<String, CertificateScope> uniqueScopes = new LinkedHashMap<>();
        for (CertificateScope scope : scopes) {
            if (scope != null) {
                uniqueScopes.putIfAbsent(scope.scopeHash(), scope);
            }
        }
        if (uniqueScopes.isEmpty()) {
            return Map.of();
        }

        Map<String, PromptQualityCertificate> certificateByScopeHash = new LinkedHashMap<>();
        List<String> hashesToLoad = new ArrayList<>();
        for (CertificateScope scope : uniqueScopes.values()) {
            RequestCertificateCacheHit requestCacheHit = requestCachedCertificate(scope);
            if (requestCacheHit.hit()) {
                certificateByScopeHash.put(scope.scopeHash(), requestCacheHit.certificate());
            } else {
                hashesToLoad.add(scope.scopeHash());
            }
        }

        if (ledgerRepository != null && !hashesToLoad.isEmpty()) {
            List<PromptQualityCertificateLedgerRecord> records =
                    ledgerRepository.findByScopeHashInOrderByRecordedAtDesc(hashesToLoad);
            if (records != null) {
                records.stream()
                        .map(this::fromRecord)
                        .filter(certificate -> certificate != null)
                        .forEach(certificate -> {
                            certificateByScopeHash.putIfAbsent(certificate.scope().scopeHash(), certificate);
                            remember(certificate);
                        });
            }
        }

        for (String scopeHash : hashesToLoad) {
            CertificateScope scope = uniqueScopes.get(scopeHash);
            PromptQualityCertificate resolved = certificateByScopeHash.get(scopeHash);
            if (resolved == null) {
                resolved = latestFromMemory(scope);
                certificateByScopeHash.put(scopeHash, resolved);
            }
            cacheRequestCertificate(scope, resolved);
        }

        Map<CertificateScope, PromptQualityCertificate> result = new LinkedHashMap<>();
        for (CertificateScope scope : scopes) {
            if (scope == null) {
                continue;
            }
            result.put(scope, certificateByScopeHash.get(scope.scopeHash()));
        }
        return result;
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PromptQualityCertificate latestFor(CertificateScope scope) {
        if (scope == null) {
            return null;
        }
        RequestCertificateCacheHit requestCacheHit = requestCachedCertificate(scope);
        if (requestCacheHit.hit()) {
            return requestCacheHit.certificate();
        }
        PromptQualityCertificate resolved = null;
        if (ledgerRepository != null) {
            PromptQualityCertificate persisted = ledgerRepository.findFirstByScopeHashOrderByRecordedAtDesc(scope.scopeHash())
                    .map(this::fromRecord)
                    .orElse(null);
            if (persisted != null) {
                remember(persisted);
                cacheRequestCertificate(scope, persisted);
                return persisted;
            }
            PromptQualityCertificate templateMatched = ledgerRepository.findTop20ByResourceIdOrderByRecordedAtDesc(scope.protectableResourceId()).stream()
                    .filter(record -> scopeMetadataMatches(record, scope))
                    .filter(record -> methodMatches(record.getHttpMethod(), scope.httpMethod()))
                    .filter(record -> pathMatches(record.getResourceUrl(), scope.resourceUrl())
                            || pathMatches(scope.resourceUrl(), record.getResourceUrl()))
                    .map(this::fromRecord)
                    .findFirst()
                    .orElse(null);
            if (templateMatched != null) {
                remember(templateMatched);
                resolved = templateMatched;
            }
        }
        if (resolved == null) {
            resolved = latestFromMemory(scope);
        }
        cacheRequestCertificate(scope, resolved);
        return resolved;
    }

    private PromptQualityCertificate latestFromMemory(CertificateScope scope) {
        if (scope == null) {
            return null;
        }
        PromptQualityCertificate cached = latestByScopeHash.get(scope.scopeHash());
        if (cached != null) {
            return cached;
        }
        return latestByScopeHash.values().stream()
                .filter(certificate -> scope.protectableResourceId().equalsIgnoreCase(certificate.scope().protectableResourceId()))
                .filter(certificate -> scopeMetadataMatches(certificate.scope(), scope))
                .filter(certificate -> methodMatches(certificate.scope().httpMethod(), scope.httpMethod()))
                .filter(certificate -> pathMatches(certificate.scope().resourceUrl(), scope.resourceUrl())
                        || pathMatches(scope.resourceUrl(), certificate.scope().resourceUrl()))
                .findFirst()
                .orElse(null);
    }

    private void remember(PromptQualityCertificate certificate) {
        if (certificate == null) {
            return;
        }
        latestByScopeHash.put(certificate.scope().scopeHash(), certificate);
        cacheRequestCertificate(certificate.scope(), certificate);
        recentCertificates.removeIf(existing -> certificate.certificateId().equals(existing.certificateId()));
        recentCertificates.add(0, certificate);
        while (recentCertificates.size() > RECENT_CERTIFICATE_LIMIT) {
            recentCertificates.remove(recentCertificates.size() - 1);
        }
    }

    @SuppressWarnings("unchecked")
    private RequestCertificateCacheHit requestCachedCertificate(CertificateScope scope) {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes == null || scope == null) {
            return RequestCertificateCacheHit.miss();
        }
        Object value = attributes.getAttribute(REQUEST_LATEST_CERTIFICATE_CACHE, RequestAttributes.SCOPE_REQUEST);
        if (!(value instanceof Map<?, ?> rawCache)) {
            return RequestCertificateCacheHit.miss();
        }
        Map<String, PromptQualityCertificate> cache = (Map<String, PromptQualityCertificate>) rawCache;
        String key = scope.scopeHash();
        if (!cache.containsKey(key)) {
            return RequestCertificateCacheHit.miss();
        }
        return RequestCertificateCacheHit.hit(cache.get(key));
    }

    @SuppressWarnings("unchecked")
    private void cacheRequestCertificate(CertificateScope scope, PromptQualityCertificate certificate) {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes == null || scope == null) {
            return;
        }
        Object value = attributes.getAttribute(REQUEST_LATEST_CERTIFICATE_CACHE, RequestAttributes.SCOPE_REQUEST);
        Map<String, PromptQualityCertificate> cache;
        if (value instanceof Map<?, ?> rawCache) {
            cache = (Map<String, PromptQualityCertificate>) rawCache;
        } else {
            cache = new LinkedHashMap<>();
            attributes.setAttribute(REQUEST_LATEST_CERTIFICATE_CACHE, cache, RequestAttributes.SCOPE_REQUEST);
        }
        cache.put(scope.scopeHash(), certificate);
    }

    private record RequestCertificateCacheHit(boolean hit, PromptQualityCertificate certificate) {
        private static RequestCertificateCacheHit hit(PromptQualityCertificate certificate) {
            return new RequestCertificateCacheHit(true, certificate);
        }

        private static RequestCertificateCacheHit miss() {
            return new RequestCertificateCacheHit(false, null);
        }
    }

    private void persist(PromptQualityCertificate certificate) {
        if (certificate == null) {
            return;
        }
        if (ledgerRepository == null) {
            syncResourceRegistry(certificate, LocalDateTime.now(KOREA_ZONE));
            persistIssueCase(certificate);
            auditCertificateDecision(certificate);
            return;
        }
        PromptQualityCertificateLedgerRecord record = new PromptQualityCertificateLedgerRecord();
        record.setCertificateId(certificate.certificateId());
        record.setState(certificate.state());
        record.setStateLabel(certificate.stateLabel());
        record.setUsableForLlmZeroTrust(certificate.usableForLlmZeroTrust());
        record.setZeroTrustState(certificate.zeroTrustState());
        record.setZeroTrustStateLabel(certificate.zeroTrustStateLabel());
        record.setResourceOperationalState(certificate.resourceOperationalState());
        record.setResourceOperationalStateLabel(certificate.resourceOperationalStateLabel());
        record.setIssuedAt(certificate.issuedAt());
        record.setTenantId(certificate.scope().tenantId());
        record.setScopeHash(certificate.scope().scopeHash());
        record.setPromptContractVersion(certificate.scope().promptContractVersion());
        record.setModelProfile(certificate.scope().modelProfile());
        record.setVerifierVersion(certificate.scope().verifierVersion());
        record.setExpiresAt(parseDateTime(certificate.expiresAt()));
        record.setRevokedAt(parseDateTime(certificate.revokedAt()));
        record.setRevokedBy(certificate.revokedBy());
        record.setRevocationReason(certificate.revocationReason());
        record.setSealedEvidencePackageId(certificate.sealedEvidencePackageId());
        record.setEvidenceSourceType(valueOrDefault(certificate.evidenceSourceType(), EVIDENCE_SOURCE_UNKNOWN));
        record.setRuntimePromptHash(certificate.runtimePromptHash());
        record.setRuntimeSystemPromptHash(certificate.runtimeSystemPromptHash());
        record.setRuntimeUserPromptHash(certificate.runtimeUserPromptHash());
        record.setRuntimeDecisionHash(certificate.runtimeDecisionHash());
        record.setPromptHash(certificate.promptHash());
        record.setSystemPromptHash(certificate.systemPromptHash());
        record.setUserPromptHash(certificate.userPromptHash());
        record.setContextHash(certificate.contextHash());
        record.setEvidenceRequestIdsJson(writeJson(certificate.evidenceRequestIds()));
        record.setRunIdsJson(writeJson(certificate.runIds()));
        record.setResourceKey(resourceKey(certificate.resourceUrl(), certificate.resourceId()));
        record.setResourceUrl(certificate.resourceUrl());
        record.setResourceId(certificate.resourceId());
        record.setHttpMethod(certificate.httpMethod());
        record.setProtectableMethod(certificate.protectableMethod());
        record.setCriticality(certificate.criticality());
        record.setVerificationRequired(certificate.verificationRequired());
        record.setTotalMetricCount(certificate.totalMetricCount());
        record.setVerifiedMetricCount(certificate.verifiedMetricCount());
        record.setFailedMetricCount(certificate.failedMetricCount());
        record.setMissingMetricCount(certificate.missingMetricCount());
        record.setSummary(certificate.summary());
        record.setBlockingFindingsJson(writeJson(certificate.blockingFindings()));
        record.setSixWJson(writeJson(certificate.sixW()));
        record.setIssueCaseJson(writeJson(certificate.issueCase()));
        record.setEvidenceLineageJson(writeJson(certificate.evidenceLineage()));
        record.setRemediationLoopJson(writeJson(certificate.remediationLoop()));
        record.setMetricsJson(writeJson(certificate.metrics()));
        record.setRecommendedActionsJson(writeJson(certificate.recommendedActions()));
        record.setRecordedAt(LocalDateTime.now(KOREA_ZONE));
        ledgerRepository.save(record);
        syncResourceRegistry(certificate, record.getRecordedAt());
        persistIssueCase(certificate);
        auditCertificateDecision(certificate);
    }

    private void persistIssueCase(PromptQualityCertificate certificate) {
        if (issueCaseRepository == null || certificate == null || certificate.issueCase() == null) {
            return;
        }
        PromptQualityIssueCase issueCase = certificate.issueCase();
        LocalDateTime now = LocalDateTime.now(KOREA_ZONE);
        PromptQualityIssueCaseRecord record = issueCaseRepository
                .findFirstByTenantIdAndScopeHashAndStateOrderByUpdatedAtDesc(
                        issueCase.tenantId(),
                        issueCase.scopeHash(),
                        issueCase.state()
                )
                .orElseGet(PromptQualityIssueCaseRecord::new);
        boolean existing = record.getId() != null;
        record.setCaseId(existing ? record.getCaseId() : issueCase.caseId());
        record.setCertificateId(certificate.certificateId());
        record.setSourceType(valueOrDefault(issueCase.sourceType(), "OFFICIAL_VERIFICATION"));
        record.setTenantId(issueCase.tenantId());
        record.setScopeHash(issueCase.scopeHash());
        record.setResourceUrl(issueCase.resourceUrl());
        record.setHttpMethod(issueCase.httpMethod());
        record.setResourceId(issueCase.resourceId());
        record.setState(issueCase.state());
        record.setSymptom(issueCase.symptom());
        record.setExpectedOutcome(issueCase.expectedOutcome());
        record.setActualOutcome(issueCase.actualOutcome());
        record.setEvidencePackageId(issueCase.evidencePackageId());
        record.setRecurrenceCount(existing ? record.getRecurrenceCount() + 1 : issueCase.recurrenceCount());
        record.setFindingsJson(writeJson(issueCase.findings()));
        record.setRecommendedActionsJson(writeJson(issueCase.recommendedActions()));
        record.setOpenedAt(parseDateTime(valueOrDefault(issueCase.openedAt(), null)) != null
                ? parseDateTime(issueCase.openedAt())
                : now);
        record.setUpdatedAt(now);
        issueCaseRepository.save(record);
    }

    private void auditCertificateDecision(PromptQualityCertificate certificate) {
        if (auditService == null || certificate == null) {
            return;
        }
        String eventType = certificate.usableForLlmZeroTrust()
                ? "CERTIFICATE_ISSUED"
                : "CERTIFICATE_BLOCKED";
        auditService.record(
                eventType,
                "official-verifier",
                certificate.scope(),
                certificate.certificateId(),
                null,
                certificate.state(),
                certificate.summary()
        );
        if (certificate.usableForLlmZeroTrust()) {
            auditService.record(
                    "RESOURCE_CERTIFIED",
                    "official-verifier",
                    certificate.scope(),
                    certificate.certificateId(),
                    "PENDING_VERIFICATION",
                    certificate.resourceOperationalState(),
                    "12 prompt-quality metrics passed. Zero Trust operation still requires explicit promotion approval."
            );
        }
    }

    private void syncResourceRegistry(PromptQualityCertificate certificate, LocalDateTime recordedAt) {
        if (registryRepository == null || certificate == null) {
            return;
        }
        LocalDateTime now = recordedAt != null ? recordedAt : LocalDateTime.now(KOREA_ZONE);
        ProtectableResourceRegistryRecord record = registryRepository.findByTenantIdAndResourceIdAndHttpMethod(
                        certificate.scope().tenantId(),
                        certificate.resourceId(),
                        certificate.httpMethod()
                )
                .orElseGet(() -> {
                    ProtectableResourceRegistryRecord created = new ProtectableResourceRegistryRecord();
                    created.setTenantId(certificate.scope().tenantId());
                    created.setResourceId(certificate.resourceId());
                    created.setHttpMethod(certificate.httpMethod());
                    created.setDiscoveredAt(now);
                    return created;
                });
        record.setResourceUrl(certificate.resourceUrl());
        record.setCriticality(certificate.criticality());
        record.setVerificationRequired(certificate.verificationRequired());
        record.setMethodIdentifier(certificate.protectableMethod());
        record.setCertificateState(certificate.state());
        record.setOperationalState(certificate.resourceOperationalState());
        record.setLatestCertificateId(certificate.certificateId());
        record.setLastVerifiedAt(now);
        record.setUpdatedAt(now);
        record.setRetired(false);
        if (!StringUtils.hasText(record.getAnnotationSignatureHash())) {
            record.setAnnotationSignatureHash(certificate.scope().scopeHash());
        }
        registryRepository.save(record);
    }

    private PromptQualityCertificate fromRecord(PromptQualityCertificateLedgerRecord record) {
        if (record == null) {
            return null;
        }
        return new PromptQualityCertificate(
                record.getCertificateId(),
                CertificateScope.of(
                        valueOrDefault(record.getTenantId(), DEFAULT_TENANT_ID),
                        record.getResourceUrl(),
                        record.getHttpMethod(),
                        record.getResourceId(),
                        valueOrDefault(record.getPromptContractVersion(), DEFAULT_PROMPT_CONTRACT_VERSION),
                        valueOrDefault(record.getModelProfile(), DEFAULT_MODEL_PROFILE),
                        valueOrDefault(record.getVerifierVersion(), DEFAULT_VERIFIER_VERSION)
                ),
                record.getState(),
                record.getStateLabel(),
                record.isUsableForLlmZeroTrust(),
                record.getZeroTrustState(),
                record.getZeroTrustStateLabel(),
                valueOrDefault(record.getResourceOperationalState(), ProtectableResourceOperationalState.PENDING_VERIFICATION.name()),
                valueOrDefault(record.getResourceOperationalStateLabel(), ProtectableResourceOperationalState.PENDING_VERIFICATION.label()),
                record.getIssuedAt(),
                formatDateTime(record.getExpiresAt()),
                formatDateTime(record.getRevokedAt()),
                record.getRevokedBy(),
                record.getRevocationReason(),
                record.getSealedEvidencePackageId(),
                valueOrDefault(record.getEvidenceSourceType(), EVIDENCE_SOURCE_UNKNOWN),
                record.getRuntimePromptHash(),
                record.getRuntimeSystemPromptHash(),
                record.getRuntimeUserPromptHash(),
                record.getRuntimeDecisionHash(),
                record.getPromptHash(),
                record.getSystemPromptHash(),
                record.getUserPromptHash(),
                record.getContextHash(),
                readStringList(record.getEvidenceRequestIdsJson()),
                readStringList(record.getRunIdsJson()),
                record.getResourceUrl(),
                record.getResourceId(),
                record.getHttpMethod(),
                record.getProtectableMethod(),
                record.getCriticality(),
                record.isVerificationRequired(),
                record.getTotalMetricCount(),
                record.getVerifiedMetricCount(),
                record.getFailedMetricCount(),
                record.getMissingMetricCount(),
                readStringList(record.getBlockingFindingsJson()),
                record.getSummary(),
                readObject(record.getSixWJson(), SixWReport.class, emptySixW()),
                readObject(record.getIssueCaseJson(), PromptQualityIssueCase.class, null),
                readObject(record.getEvidenceLineageJson(), EvidenceLineage.class, emptyEvidenceLineage()),
                readObject(record.getRemediationLoopJson(), RemediationLoop.class, emptyRemediationLoop()),
                readMetricList(record.getMetricsJson()),
                readStringList(record.getRecommendedActionsJson())
        );
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public PromptQualityCertificate revoke(String certificateId, String revokedBy, String reason) {
        return transitionStoredCertificate(
                certificateId,
                PromptQualityCertificateState.REVOKED,
                ProtectableResourceOperationalState.SUSPENDED,
                valueOrDefault(revokedBy, "system"),
                valueOrDefault(reason, "Operator revoked the prompt quality certificate.")
        );
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public PromptQualityCertificate expire(String certificateId, String reason) {
        return transitionStoredCertificate(
                certificateId,
                PromptQualityCertificateState.EXPIRED,
                ProtectableResourceOperationalState.EXPIRED,
                null,
                valueOrDefault(reason, "Prompt quality certificate expired or requires re-verification.")
        );
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PromptQualityCertificate findByCertificateId(String certificateId) {
        if (!StringUtils.hasText(certificateId)) {
            return null;
        }
        if (ledgerRepository != null) {
            PromptQualityCertificate persisted = ledgerRepository.findFirstByCertificateIdOrderByRecordedAtDesc(certificateId)
                    .map(this::fromRecord)
                    .orElse(null);
            if (persisted != null) {
                remember(persisted);
                return persisted;
            }
        }
        return recentCertificates.stream()
                .filter(item -> certificateId.equals(item.certificateId()))
                .findFirst()
                .orElse(null);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PromptQualityCertificate findLatestBySealedEvidencePackageId(String packageId) {
        if (!StringUtils.hasText(packageId)) {
            return null;
        }
        String normalizedPackageId = packageId.trim();
        if (ledgerRepository != null) {
            PromptQualityCertificate persisted = ledgerRepository
                    .findFirstBySealedEvidencePackageIdOrderByRecordedAtDesc(normalizedPackageId)
                    .map(this::fromRecord)
                    .orElse(null);
            if (persisted != null) {
                remember(persisted);
                return persisted;
            }
        }
        return recentCertificates.stream()
                .filter(item -> normalizedPackageId.equals(item.sealedEvidencePackageId()))
                .findFirst()
                .orElse(null);
    }


    private PromptQualityCertificate transitionStoredCertificate(
            String certificateId,
            PromptQualityCertificateState certificateState,
            ProtectableResourceOperationalState operationalState,
            String revokedBy,
            String reason
    ) {
        if (!StringUtils.hasText(certificateId)) {
            return null;
        }
        LocalDateTime now = LocalDateTime.now(KOREA_ZONE);
        if (ledgerRepository != null) {
            PromptQualityCertificateLedgerRecord record = ledgerRepository.findFirstByCertificateIdOrderByRecordedAtDesc(certificateId)
                    .orElse(null);
            if (record == null) {
                return null;
            }
            String previousState = record.getState();
            stateMachine.requireCertificateTransition(previousState, certificateState);
            stateMachine.requireResourceTransition(record.getResourceOperationalState(), operationalState);
            record.setState(certificateState.name());
            record.setStateLabel(certificateState.label());
            record.setUsableForLlmZeroTrust(false);
            record.setZeroTrustState(operationalState.name());
            record.setZeroTrustStateLabel(operationalState.label());
            record.setResourceOperationalState(operationalState.name());
            record.setResourceOperationalStateLabel(operationalState.label());
            if (certificateState == PromptQualityCertificateState.EXPIRED) {
                record.setExpiresAt(now);
            }
            if (certificateState == PromptQualityCertificateState.REVOKED) {
                record.setRevokedAt(now);
                record.setRevokedBy(revokedBy);
                record.setRevocationReason(reason);
            }
            record.setSummary(reason);
            ledgerRepository.save(record);
            PromptQualityCertificate transitioned = fromRecord(record);
            remember(transitioned);
            syncResourceRegistry(transitioned, now);
            auditTransition(transitioned, previousState, certificateState.name(), revokedBy, reason);
            return transitioned;
        }
        PromptQualityCertificate existing = recentCertificates.stream()
                .filter(item -> certificateId.equals(item.certificateId()))
                .findFirst()
                .orElse(null);
        if (existing == null) {
            return null;
        }
        PromptQualityCertificate transitioned = transitionedCertificate(existing, certificateState, operationalState, revokedBy, reason, now);
        remember(transitioned);
        syncResourceRegistry(transitioned, now);
        auditTransition(transitioned, existing.state(), certificateState.name(), revokedBy, reason);
        return transitioned;
    }

    private void auditTransition(
            PromptQualityCertificate certificate,
            String previousState,
            String nextState,
            String actor,
            String reason
    ) {
        if (auditService == null || certificate == null) {
            return;
        }
        String eventType = switch (nextState) {
            case "EXPIRED" -> "CERTIFICATE_EXPIRED";
            case "REVOKED" -> "CERTIFICATE_REVOKED";
            default -> "CERTIFICATE_STATE_CHANGED";
        };
        auditService.record(
                eventType,
                valueOrDefault(actor, "system"),
                certificate.scope(),
                certificate.certificateId(),
                previousState,
                nextState,
                reason
        );
    }


    private PromptQualityCertificate transitionedCertificate(
            PromptQualityCertificate existing,
            PromptQualityCertificateState certificateState,
            ProtectableResourceOperationalState operationalState,
            String revokedBy,
            String reason,
            LocalDateTime now
    ) {
        return new PromptQualityCertificate(
                existing.certificateId(),
                existing.scope(),
                certificateState.name(),
                certificateState.label(),
                false,
                operationalState.name(),
                operationalState.label(),
                operationalState.name(),
                operationalState.label(),
                existing.issuedAt(),
                certificateState == PromptQualityCertificateState.EXPIRED ? now.toString() : existing.expiresAt(),
                certificateState == PromptQualityCertificateState.REVOKED ? now.toString() : existing.revokedAt(),
                certificateState == PromptQualityCertificateState.REVOKED ? valueOrDefault(revokedBy, "system") : existing.revokedBy(),
                StringUtils.hasText(reason) ? reason : existing.revocationReason(),
                existing.sealedEvidencePackageId(),
                existing.evidenceSourceType(),
                existing.runtimePromptHash(),
                existing.runtimeSystemPromptHash(),
                existing.runtimeUserPromptHash(),
                existing.runtimeDecisionHash(),
                existing.promptHash(),
                existing.systemPromptHash(),
                existing.userPromptHash(),
                existing.contextHash(),
                existing.evidenceRequestIds(),
                existing.runIds(),
                existing.resourceUrl(),
                existing.resourceId(),
                existing.httpMethod(),
                existing.protectableMethod(),
                existing.criticality(),
                existing.verificationRequired(),
                existing.totalMetricCount(),
                existing.verifiedMetricCount(),
                existing.failedMetricCount(),
                existing.missingMetricCount(),
                existing.blockingFindings(),
                StringUtils.hasText(reason) ? reason : existing.summary(),
                existing.sixW(),
                existing.issueCase(),
                existing.evidenceLineage(),
                existing.remediationLoop(),
                existing.metrics(),
                existing.recommendedActions()
        );
    }

    private PromptQualityIssueCase issueCase(
            String certificateId,
            CertificateScope scope,
            String state,
            List<String> blockingFindings,
            List<String> recommendedActions,
            String generatedAt,
            List<MetricRunEvidence> evidence
    ) {
        String issueState = "ISSUED".equalsIgnoreCase(state) ? "CLOSED" : "OPEN";
        List<String> findings = blockingFindings == null ? List.of() : blockingFindings;
        List<String> actions = recommendedActions == null ? List.of() : recommendedActions;
        return new PromptQualityIssueCase(
                "pqc-case-" + certificateId,
                certificateId,
                "OFFICIAL_VERIFICATION",
                scope.tenantId(),
                scope.scopeHash(),
                scope.resourceUrl(),
                scope.httpMethod(),
                scope.protectableResourceId(),
                issueState,
                valueOrDefault(generatedAt, LocalDateTime.now(KOREA_ZONE).toString()),
                findings.isEmpty() ? PromptQualityCertificateNarrative.noBlockingFinding() : findings.get(0),
                PromptQualityCertificateNarrative.issueRequiredOutcome(),
                PromptQualityCertificateNarrative.issueCause(state),
                evidencePackageId(scope, evidence),
                0,
                findings,
                actions
        );
    }

    private EvidenceLineage evidenceLineage(
            String certificateId,
            CertificateScope scope,
            List<MetricRunEvidence> evidence,
            List<MetricCertificateItem> metricItems,
            String requestContextHash,
            String learningContextHash,
            String systemPromptHash,
            String userPromptHash
    ) {
        return new EvidenceLineage(
                scope.scopeHash(),
                scope.tenantId(),
                scope.resourceUrl(),
                scope.httpMethod(),
                scope.protectableResourceId(),
                requestContextHash,
                learningContextHash,
                systemPromptHash,
                userPromptHash,
                llmDecisionId(evidence),
                certificateId,
                evidenceRequestIds(evidence),
                runIds(metricItems),
                metricItems == null
                        ? List.of()
                        : metricItems.stream()
                        .map(item -> item.metricCode() + ":" + valueOrDefault(item.runId(), "missing"))
                        .toList()
        );
    }

    private RemediationLoop remediationLoop(
            String state,
            List<String> blockingFindings,
            List<String> recommendedActions
    ) {
        boolean passed = "ISSUED".equalsIgnoreCase(state);
        return new RemediationLoop(
                passed ? "CLOSED" : "REVERIFY_REQUIRED",
                PromptQualityCertificateNarrative.remediationSummary(passed),
                recommendedActions == null ? List.of() : recommendedActions,
                blockingFindings == null ? List.of() : blockingFindings,
                PromptQualityCertificateNarrative.reverifyCriteria()
        );
    }

    private MetricCertificateItem metricItem(
            OfficialVerificationMetricDefinition metric,
            MetricRunEvidence evidence,
            List<MetricExecutionFailure> failures
    ) {
        MetricExecutionFailure failure = failures == null ? null : failures.stream()
                .filter(item -> normalizeMetricCode(item.metricCode()).equals(normalizeMetricCode(metric.code())))
                .findFirst()
                .orElse(null);
        if (failure != null) {
            return new MetricCertificateItem(
                    metric.code(),
                    metric.metricName(),
                    metric.category(),
                    "FAILED",
                    false,
                    null,
                    metric.benchmarkSuccessThreshold(),
                    metric.higherIsBetter(),
                    null,
                    null,
                    PromptQualityCertificateNarrative.metricExecutionFailureSummary(failure.message()),
                    metricMeaning(metric),
                    metricEvidenceScope(metric),
                    PromptQualityCertificateNarrative.metricExecutionFailureAction(),
                    metricDiagnostic(metric, "FAILED", false, null, failure,
                            PromptQualityCertificateNarrative.metricExecutionFailureCause(),
                            PromptQualityCertificateNarrative.metricExecutionFailureRemediation())
            );
        }
        if (evidence == null || evidence.run() == null) {
            return new MetricCertificateItem(
                    metric.code(),
                    metric.metricName(),
                    metric.category(),
                    "MISSING",
                    false,
                    null,
                    metric.benchmarkSuccessThreshold(),
                    metric.higherIsBetter(),
                    null,
                    null,
                    PromptQualityCertificateNarrative.metricMissingSummary(),
                    metricMeaning(metric),
                    metricEvidenceScope(metric),
                    PromptQualityCertificateNarrative.metricMissingAction(),
                    metricDiagnostic(metric, "MISSING", false, null, null,
                            PromptQualityCertificateNarrative.metricMissingCause(),
                            PromptQualityCertificateNarrative.metricMissingRemediation())
            );
        }

        OfficialVerificationRunView run = evidence.run();
        boolean notApplicable = runNotApplicable(run);
        boolean verified = runVerified(metric, run);
        return new MetricCertificateItem(
                metric.code(),
                metric.metricName(),
                metric.category(),
                notApplicable ? "NOT_APPLICABLE" : verified ? "VERIFIED" : "FAILED",
                verified,
                run.score(),
                metric.benchmarkSuccessThreshold(),
                metric.higherIsBetter(),
                run.runId(),
                run.processingTimeMs(),
                verified ? PromptQualityCertificateNarrative.metricVerifiedSummary() : failedRunSummary(run),
                metricMeaning(metric),
                metricEvidenceScope(metric),
                verified
                        ? PromptQualityCertificateNarrative.metricVerifiedAction()
                        : PromptQualityCertificateNarrative.metricFailedAction(),
                metricDiagnostic(
                        metric,
                        verified ? "VERIFIED" : "FAILED",
                        verified,
                        run,
                        null,
                        verified
                                ? PromptQualityCertificateNarrative.metricVerifiedCause()
                                : PromptQualityCertificateNarrative.metricFailedCause(),
                        verified
                                ? PromptQualityCertificateNarrative.metricVerifiedRemediation()
                                : PromptQualityCertificateNarrative.metricFailedRemediation()
                )
        );
    }

    private MetricDiagnosticReport metricDiagnostic(
            OfficialVerificationMetricDefinition metric,
            String state,
            boolean verified,
            OfficialVerificationRunView run,
            MetricExecutionFailure failure,
            String cause,
            String remediation
    ) {
        String metricCode = normalizeMetricCode(metric.code());
        String impact = PromptQualityCertificateNarrative.metricImpact(verified);
        String reverify = PromptQualityCertificateNarrative.metricReverify(verified);
        String evidencePath = run != null
                ? "요청 증거와 지표 실행 기록이 공식 원장에서 서로 연결되어 있습니다."
                : PromptQualityCertificateNarrative.noExecutionEvidence();
        String ownerHint = PromptQualityCertificateNarrative.ownerHint(metric);
        String meaning = metricMeaning(metric);
        MetricDiagnosticSixW sixW = new MetricDiagnosticSixW(
                run != null ? valueOrDefault(run.completedAt(), valueOrDefault(run.startedAt(), "검증 실행 시점")) : "검증 실행 증거 없음",
                metric.metricName() + " 지표 / " + evidencePath,
                "공식검증기",
                metric.metricName() + " 지표",
                metricEvidenceScope(metric) + "를 기준으로 점수, 체크 통과, 증거 연결을 확인했습니다.",
                meaning,
                verified ? "통과했습니다. 이 지표는 보증서 발급을 막지 않습니다." : "실패 또는 미실행 상태입니다. 조치 후 같은 scope로 재검증해야 합니다."
        );
        return new MetricDiagnosticReport(
                metricCode,
                state,
                cause,
                failure != null ? valueOrDefault(failure.message(), PromptQualityCertificateNarrative.metricFailureFallback()) : impact,
                remediation,
                reverify,
                evidencePath,
                ownerHint,
                sixW
        );
    }

    private boolean runVerified(OfficialVerificationMetricDefinition metric, OfficialVerificationRunView run) {
        if (runNotApplicable(run)) {
            return true;
        }
        if (run == null || run.totalChecks() <= 0) {
            return false;
        }
        boolean allChecksPassed = run.passedChecks() >= run.totalChecks();
        String tone = run.stateTone() != null ? run.stateTone().trim().toLowerCase(Locale.ROOT) : "";
        String state = run.state() != null ? run.state().trim().toLowerCase(Locale.ROOT) : "";
        boolean passState = "success".equals(tone)
                || state.equals("success")
                || state.contains("threshold passed")
                || state.contains("verified")
                || state.equals("pass")
                || state.equals("passed");
        boolean scorePassed = metric.higherIsBetter()
                ? run.score() >= metric.benchmarkSuccessThreshold()
                : run.score() <= metric.benchmarkSuccessThreshold();
        return allChecksPassed && passState && scorePassed;
    }

    private boolean runNotApplicable(OfficialVerificationRunView run) {
        if (run == null) {
            return false;
        }
        String state = run.state() != null ? run.state().trim().toUpperCase(Locale.ROOT) : "";
        String tone = run.stateTone() != null ? run.stateTone().trim().toUpperCase(Locale.ROOT) : "";
        return "NOT_APPLICABLE".equals(state) || "NOT_APPLICABLE".equals(tone);
    }

    private String failedRunSummary(OfficialVerificationRunView run) {
        if (run == null) {
            return PromptQualityCertificateNarrative.noRunSummary();
        }
        return PromptQualityCertificateNarrative.failedRunSummary(
                run.passedChecks(),
                run.totalChecks(),
                run.state(),
                run.score(),
                run.message()
        );
    }

    private List<String> blockingFindings(
            boolean protectablePresent,
            boolean verificationRequired,
            List<MetricCertificateItem> metricItems,
            List<MetricExecutionFailure> failures
    ) {
        List<String> findings = new ArrayList<>();
        if (!protectablePresent) {
            findings.add(PromptQualityCertificateNarrative.protectableMissingFinding());
        }
        if (protectablePresent && !verificationRequired) {
            findings.add(PromptQualityCertificateNarrative.verificationDisabledFinding());
        }
        metricItems.stream()
                .filter(item -> !item.verified())
                .limit(15)
                .forEach(item -> findings.add(PromptQualityCertificateNarrative.metricStateFinding(item.metricCode(), item.state(), item.summary())));
        if (failures != null) {
            failures.stream()
                    .limit(5)
                    .forEach(failure -> findings.add(PromptQualityCertificateNarrative.metricExecutionFailureFinding(failure.metricCode(), failure.message())));
        }
        return List.copyOf(findings);
    }

    private List<String> recommendedActions(
            boolean protectablePresent,
            boolean verificationRequired,
            List<MetricCertificateItem> metricItems,
            List<MetricExecutionFailure> failures
    ) {
        List<String> actions = new ArrayList<>();
        if (!protectablePresent) {
            actions.add(PromptQualityCertificateNarrative.protectableMissingAction());
        }
        if (protectablePresent && !verificationRequired) {
            actions.add(PromptQualityCertificateNarrative.verificationDisabledAction());
        }
        metricItems.stream()
                .filter(item -> !item.verified())
                .map(MetricCertificateItem::recommendedAction)
                .filter(StringUtils::hasText)
                .distinct()
                .forEach(actions::add);
        if (failures != null && !failures.isEmpty()) {
            actions.add(PromptQualityCertificateNarrative.executionFailureAction());
        }
        return actions.isEmpty()
                ? List.of(PromptQualityCertificateNarrative.defaultSuccessAction())
                : List.copyOf(actions);
    }

    private String metricMeaning(OfficialVerificationMetricDefinition metric) {
        return PromptQualityCertificateNarrative.metricMeaning(metric);
    }

    private String metricEvidenceScope(OfficialVerificationMetricDefinition metric) {
        return PromptQualityCertificateNarrative.metricEvidenceScope(metric);
    }

    private List<String> evidenceRequestIds(List<MetricRunEvidence> evidence) {
        if (evidence == null) {
            return List.of();
        }
        return evidence.stream()
                .map(MetricRunEvidence::run)
                .filter(run -> run != null && StringUtils.hasText(run.requestId()))
                .map(OfficialVerificationRunView::requestId)
                .distinct()
                .toList();
    }

    private List<String> runIds(List<MetricCertificateItem> metricItems) {
        if (metricItems == null) {
            return List.of();
        }
        return metricItems.stream()
                .map(MetricCertificateItem::runId)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private String evidenceHash(List<MetricRunEvidence> evidence, String slice) {
        if (evidence == null || evidence.isEmpty()) {
            return sha256(slice + "|empty");
        }
        List<Map<String, Object>> material = evidence.stream()
                .map(item -> {
                    Map<String, Object> facts = new LinkedHashMap<>();
                    facts.put("metric", item != null ? item.metricCode() : "unknown");
                    OfficialVerificationRunView run = item != null ? item.run() : null;
                    if (run == null) {
                        facts.put("missing", true);
                        return facts;
                    }
                    switch (slice) {
                        case "request-context" -> {
                            facts.put("requestFacts", run.requestFacts());
                            facts.put("eventFacts", run.eventFacts());
                        }
                        case "learning-context" -> {
                            facts.put("analysisFacts", run.analysisFacts());
                            facts.put("rawEvidence", run.rawEvidence());
                        }
                        case "system-prompt", "user-prompt" -> facts.put("promptFacts", run.promptFacts());
                        default -> {
                            facts.put("runId", valueOrDefault(run.runId(), "n/a"));
                            facts.put("requestId", valueOrDefault(run.requestId(), "n/a"));
                        }
                    }
                    return facts;
                })
                .toList();
        return sha256(slice + "|" + writeJson(material));
    }

    private String llmDecisionId(List<MetricRunEvidence> evidence) {
        return null;
    }

    private RuntimeEvidenceSource runtimeEvidenceSource(List<MetricRunEvidence> evidence) {
        String packageId = firstRunEvidenceValue(
                evidence,
                "sealedEvidencePackageId",
                "runtimeEvidencePackageId",
                "packageId");
        String sourceMode = firstRunEvidenceValue(evidence, "sourceMode", "evidenceSourceType");
        boolean sealedRuntimeSource = StringUtils.hasText(packageId) && (
                "RUNTIME_SEALED_EVIDENCE".equalsIgnoreCase(sourceMode)
                        || "CORE_OFFICIAL_SEALED_EVIDENCE".equalsIgnoreCase(sourceMode)
                        || EVIDENCE_SOURCE_SEALED_RUNTIME_PACKAGE.equalsIgnoreCase(sourceMode));
        String sourceType = sealedRuntimeSource
                ? EVIDENCE_SOURCE_SEALED_RUNTIME_PACKAGE
                : evidence == null || evidence.isEmpty()
                ? EVIDENCE_SOURCE_UNKNOWN
                : EVIDENCE_SOURCE_OFFICIAL_VERIFICATION_RUN;
        return new RuntimeEvidenceSource(
                packageId,
                sourceType,
                firstRunEvidenceValue(evidence, "runtimePromptHash", "promptHash", "llmPromptHash"),
                firstRunEvidenceValue(evidence, "runtimeSystemPromptHash", "systemPromptHash", "llmSystemPromptHash"),
                firstRunEvidenceValue(evidence, "runtimeUserPromptHash", "userPromptHash", "llmUserPromptHash"),
                firstRunEvidenceValue(evidence, "runtimeDecisionHash", "decisionHash", "llmDecisionHash")
        );
    }

    private String firstRunEvidenceValue(List<MetricRunEvidence> evidence, String... keys) {
        if (evidence == null || keys == null) {
            return null;
        }
        for (MetricRunEvidence item : evidence) {
            OfficialVerificationRunView run = item != null ? item.run() : null;
            if (run == null) {
                continue;
            }
            String value = firstRawEvidenceValue(run.rawEvidence(), keys);
            if (!StringUtils.hasText(value)) {
                value = firstStringMapValue(run.promptFacts(), keys);
            }
            if (!StringUtils.hasText(value)) {
                value = firstStringMapValue(run.analysisFacts(), keys);
            }
            if (!StringUtils.hasText(value)) {
                value = firstStringMapValue(run.eventFacts(), keys);
            }
            if (StringUtils.hasText(value)) {
                return value;
            }
        }
        return null;
    }

    private String evidencePackageId(CertificateScope scope, List<MetricRunEvidence> evidence) {
        String sealedEvidencePackageId = evidence == null ? null : evidence.stream()
                .filter(item -> item != null && item.run() != null && item.run().rawEvidence() != null)
                .map(item -> firstRawEvidenceValue(
                        item.run().rawEvidence(),
                        "sealedEvidencePackageId",
                        "runtimeEvidencePackageId",
                        "packageId"))
                .filter(StringUtils::hasText)
                .findFirst()
                .orElse(null);
        if (StringUtils.hasText(sealedEvidencePackageId)) {
            return sealedEvidencePackageId;
        }
        return scope == null ? null : "pqc-evidence-" + scope.scopeHash();
    }

    private String firstRawEvidenceValue(Map<String, Object> rawEvidence, String... keys) {
        if (rawEvidence == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            Object value = rawEvidence.get(key);
            if (value != null && StringUtils.hasText(String.valueOf(value))) {
                return String.valueOf(value).trim();
            }
        }
        return null;
    }

    private String firstStringMapValue(Map<String, String> source, String... keys) {
        if (source == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            String value = source.get(key);
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private String sha256(String material) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(valueOrDefault(material, "").getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available.", exception);
        }
    }


    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        }
        catch (JsonProcessingException exception) {
            return "null";
        }
    }

    private List<String> readStringList(String json) {
        if (!StringUtils.hasText(json)) {
            return List.of();
        }
        try {
            JavaType type = objectMapper.getTypeFactory().constructCollectionType(List.class, String.class);
            return objectMapper.readValue(json, type);
        }
        catch (JsonProcessingException exception) {
            return List.of();
        }
    }

    private List<MetricCertificateItem> readMetricList(String json) {
        if (!StringUtils.hasText(json)) {
            return List.of();
        }
        try {
            JavaType type = objectMapper.getTypeFactory().constructCollectionType(List.class, MetricCertificateItem.class);
            return objectMapper.readValue(json, type);
        }
        catch (JsonProcessingException exception) {
            return List.of();
        }
    }

    private <T> T readObject(String json, Class<T> type, T fallback) {
        if (!StringUtils.hasText(json)) {
            return fallback;
        }
        try {
            return objectMapper.readValue(json, type);
        }
        catch (JsonProcessingException exception) {
            return fallback;
        }
    }

    private SixWReport emptySixW() {
        return PromptQualityCertificateNarrative.emptySixW();
    }

    private EvidenceLineage emptyEvidenceLineage() {
        return new EvidenceLineage("n/a", "default", "n/a", "GET", "n/a", null, null, null, null, null, null, List.of(), List.of(), List.of());
    }

    private RemediationLoop emptyRemediationLoop() {
        return new RemediationLoop(
                "UNKNOWN",
                PromptQualityCertificateNarrative.emptyRemediationSummary(),
                List.of(),
                List.of(),
                PromptQualityCertificateNarrative.emptyRemediationReverifyCriteria()
        );
    }

    private LocalDateTime parseDateTime(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        try {
            return LocalDateTime.parse(value.trim());
        }
        catch (RuntimeException ignored) {
            return null;
        }
    }

    private String formatDateTime(LocalDateTime value) {
        return value != null ? value.toString() : null;
    }

    private String normalizeMetricCode(String metricCode) {
        return metricCode == null ? "" : metricCode.trim().toUpperCase(Locale.ROOT);
    }

    private String resourceKey(String resourceUrl, String resourceId) {
        return (valueOrDefault(resourceUrl, "n/a") + "|" + valueOrDefault(resourceId, "n/a")).toLowerCase(Locale.ROOT);
    }

    private boolean pathMatches(String declaredUrl, String requestPath) {
        if (!StringUtils.hasText(declaredUrl) || !StringUtils.hasText(requestPath)) {
            return false;
        }
        String declared = normalizePath(declaredUrl);
        String requested = normalizePath(requestPath);
        if (declared.equalsIgnoreCase(requested)) {
            return true;
        }
        String[] declaredParts = declared.split("/");
        String[] requestedParts = requested.split("/");
        if (declaredParts.length != requestedParts.length) {
            return false;
        }
        for (int index = 0; index < declaredParts.length; index++) {
            String declaredPart = declaredParts[index];
            if (declaredPart.startsWith("{") && declaredPart.endsWith("}")) {
                continue;
            }
            if (!declaredPart.equalsIgnoreCase(requestedParts[index])) {
                return false;
            }
        }
        return true;
    }

    private boolean methodMatches(String declaredMethod, String requestMethod) {
        return valueOrDefault(declaredMethod, "GET").equalsIgnoreCase(valueOrDefault(requestMethod, "GET"));
    }

    private boolean scopeMetadataMatches(PromptQualityCertificateLedgerRecord record, CertificateScope requestedScope) {
        if (record == null || requestedScope == null) {
            return false;
        }
        return equalsIgnoreCase(valueOrDefault(record.getTenantId(), DEFAULT_TENANT_ID), requestedScope.tenantId())
                && equalsIgnoreCase(valueOrDefault(record.getPromptContractVersion(), DEFAULT_PROMPT_CONTRACT_VERSION), requestedScope.promptContractVersion())
                && equalsIgnoreCase(valueOrDefault(record.getModelProfile(), DEFAULT_MODEL_PROFILE), requestedScope.modelProfile())
                && equalsIgnoreCase(valueOrDefault(record.getVerifierVersion(), DEFAULT_VERIFIER_VERSION), requestedScope.verifierVersion());
    }

    private boolean scopeMetadataMatches(CertificateScope issuedScope, CertificateScope requestedScope) {
        if (issuedScope == null || requestedScope == null) {
            return false;
        }
        return equalsIgnoreCase(issuedScope.tenantId(), requestedScope.tenantId())
                && equalsIgnoreCase(issuedScope.promptContractVersion(), requestedScope.promptContractVersion())
                && equalsIgnoreCase(issuedScope.modelProfile(), requestedScope.modelProfile())
                && equalsIgnoreCase(issuedScope.verifierVersion(), requestedScope.verifierVersion());
    }

    private boolean equalsIgnoreCase(String left, String right) {
        return valueOrDefault(left, "n/a").equalsIgnoreCase(valueOrDefault(right, "n/a"));
    }

    private String normalizePath(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String normalized = value.trim();
        int queryIndex = normalized.indexOf('?');
        if (queryIndex >= 0) {
            normalized = normalized.substring(0, queryIndex);
        }
        while (normalized.endsWith("/") && normalized.length() > 1) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String valueOrDefault(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    public record MetricRunEvidence(String metricCode, OfficialVerificationRunView run) {
    }

    public record MetricExecutionFailure(String metricCode, String message) {
    }

    public record CertificateScope(
            String tenantId,
            String resourceUrl,
            String httpMethod,
            String protectableResourceId,
            String promptContractVersion,
            String modelProfile,
            String verifierVersion,
            String scopeHash) {

        public static CertificateScope of(
                String tenantId,
                String resourceUrl,
                String httpMethod,
                String protectableResourceId,
                String promptContractVersion,
                String modelProfile,
                String verifierVersion
        ) {
            String normalizedTenant = normalized(valueOrDefaultStatic(tenantId, DEFAULT_TENANT_ID));
            String normalizedUrl = normalizePathStatic(valueOrDefaultStatic(resourceUrl, "n/a"));
            String normalizedMethod = valueOrDefaultStatic(httpMethod, "GET").trim().toUpperCase(Locale.ROOT);
            String normalizedResource = normalized(valueOrDefaultStatic(protectableResourceId, "n/a"));
            String normalizedPromptContract = normalized(valueOrDefaultStatic(promptContractVersion, DEFAULT_PROMPT_CONTRACT_VERSION));
            String normalizedModel = normalized(valueOrDefaultStatic(modelProfile, DEFAULT_MODEL_PROFILE));
            String normalizedVerifier = normalized(valueOrDefaultStatic(verifierVersion, DEFAULT_VERIFIER_VERSION));
            String material = String.join("|",
                    normalizedTenant,
                    normalizedUrl,
                    normalizedMethod,
                    normalizedResource,
                    normalizedPromptContract,
                    normalizedModel,
                    normalizedVerifier
            );
            return new CertificateScope(
                    normalizedTenant,
                    normalizedUrl,
                    normalizedMethod,
                    normalizedResource,
                    normalizedPromptContract,
                    normalizedModel,
                    normalizedVerifier,
                    sha256(material)
            );
        }

        private static String normalized(String value) {
            return valueOrDefaultStatic(value, "n/a").trim().toLowerCase(Locale.ROOT);
        }

        private static String valueOrDefaultStatic(String value, String fallback) {
            return StringUtils.hasText(value) ? value.trim() : fallback;
        }

        private static String normalizePathStatic(String value) {
            String normalized = valueOrDefaultStatic(value, "").trim();
            int queryIndex = normalized.indexOf('?');
            if (queryIndex >= 0) {
                normalized = normalized.substring(0, queryIndex);
            }
            while (normalized.endsWith("/") && normalized.length() > 1) {
                normalized = normalized.substring(0, normalized.length() - 1);
            }
            return normalized.toLowerCase(Locale.ROOT);
        }

        private static String sha256(String material) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                return HexFormat.of().formatHex(digest.digest(material.getBytes(StandardCharsets.UTF_8)));
            }
            catch (NoSuchAlgorithmException exception) {
                throw new IllegalStateException("SHA-256 is not available.", exception);
            }
        }
    }

    public enum PromptQualityCertificateState {
        ISSUED("품질 보증서 발급"),
        REVIEW_REQUIRED("검토 필요"),
        BLOCKED("품질 보증서 발급 차단"),
        EXPIRED("품질 보증서 만료"),
        REVOKED("품질 보증서 폐기");

        private final String label;

        PromptQualityCertificateState(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    public enum ProtectableResourceOperationalState {
        DISCOVERED("리소스 발견"),
        PENDING_VERIFICATION("검증 대기"),
        CERTIFIED("보증 완료"),
        ZERO_TRUST_ENABLED("제로트러스트 허용"),
        BLOCKED("제로트러스트 차단"),
        SUSPENDED("제로트러스트 정지"),
        EXPIRED("보증 만료"),
        RETIRED("리소스 폐기");

        private final String label;

        ProtectableResourceOperationalState(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    public record PromptQualityCertificate(
            String certificateId,
            CertificateScope scope,
            String state,
            String stateLabel,
            boolean usableForLlmZeroTrust,
            String zeroTrustState,
            String zeroTrustStateLabel,
            String resourceOperationalState,
            String resourceOperationalStateLabel,
            String issuedAt,
            String expiresAt,
            String revokedAt,
            String revokedBy,
            String revocationReason,
            String sealedEvidencePackageId,
            String evidenceSourceType,
            String runtimePromptHash,
            String runtimeSystemPromptHash,
            String runtimeUserPromptHash,
            String runtimeDecisionHash,
            String promptHash,
            String systemPromptHash,
            String userPromptHash,
            String contextHash,
            List<String> evidenceRequestIds,
            List<String> runIds,
            String resourceUrl,
            String resourceId,
            String httpMethod,
            String protectableMethod,
            String criticality,
            boolean verificationRequired,
            int totalMetricCount,
            int verifiedMetricCount,
            int failedMetricCount,
            int missingMetricCount,
            List<String> blockingFindings,
            String summary,
            SixWReport sixW,
            PromptQualityIssueCase issueCase,
            EvidenceLineage evidenceLineage,
            RemediationLoop remediationLoop,
            List<MetricCertificateItem> metrics,
            List<String> recommendedActions) {

        public boolean currentlyValidForRuntime() {
            if (!usableForLlmZeroTrust || !"ISSUED".equalsIgnoreCase(state)) {
                return false;
            }
            if (!EVIDENCE_SOURCE_SEALED_RUNTIME_PACKAGE.equalsIgnoreCase(evidenceSourceType)
                    || !StringUtils.hasText(sealedEvidencePackageId)
                    || !StringUtils.hasText(runtimePromptHash)
                    || failedMetricCount > 0
                    || (remediationLoop != null && "REVERIFY_REQUIRED".equalsIgnoreCase(remediationLoop.state()))) {
                return false;
            }
            if (StringUtils.hasText(revokedAt)) {
                return false;
            }
            if (!StringUtils.hasText(expiresAt)) {
                return true;
            }
            try {
                return !LocalDateTime.parse(expiresAt).isBefore(LocalDateTime.now(KOREA_ZONE));
            }
            catch (RuntimeException ignored) {
                return false;
            }
        }
    }

    public record SixWReport(
            String when,
            String where,
            String who,
            String what,
            String how,
            String why,
            String result) {
    }

    public record PromptQualityIssueCase(
            String caseId,
            String certificateId,
            String sourceType,
            String tenantId,
            String scopeHash,
            String resourceUrl,
            String httpMethod,
            String resourceId,
            String state,
            String openedAt,
            String symptom,
            String expectedOutcome,
            String actualOutcome,
            String evidencePackageId,
            int recurrenceCount,
            List<String> findings,
            List<String> recommendedActions) {
    }

    public record EvidenceLineage(
            String scopeHash,
            String tenantId,
            String resourceUrl,
            String httpMethod,
            String resourceId,
            String requestContextHash,
            String learningContextHash,
            String finalSystemPromptHash,
            String finalUserPromptHash,
            String llmDecisionId,
            String certificateId,
            List<String> requestIds,
            List<String> runIds,
            List<String> metricEvidenceRefs) {
    }

    public record RemediationLoop(
            String state,
            String nextStep,
            List<String> actions,
            List<String> findings,
            String reverifyCriterion) {
    }

    private record RuntimeEvidenceSource(
            String sealedEvidencePackageId,
            String evidenceSourceType,
            String runtimePromptHash,
            String runtimeSystemPromptHash,
            String runtimeUserPromptHash,
            String runtimeDecisionHash) {
    }

    public record MetricCertificateItem(
            String metricCode,
            String metricName,
            String category,
            String state,
            boolean verified,
            Double score,
            double threshold,
            boolean higherIsBetter,
            String runId,
            Long processingTimeMs,
            String summary,
            String plainMeaning,
            String evidenceScope,
            String recommendedAction,
            MetricDiagnosticReport diagnostic) {
    }

    public record MetricDiagnosticReport(
            String metricCode,
            String state,
            String cause,
            String impact,
            String remediation,
            String reverifyCriterion,
            String evidencePath,
            String ownerHint,
            MetricDiagnosticSixW sixW) {
    }

    public record MetricDiagnosticSixW(
            String when,
            String where,
            String who,
            String what,
            String how,
            String why,
            String result) {
    }

}
