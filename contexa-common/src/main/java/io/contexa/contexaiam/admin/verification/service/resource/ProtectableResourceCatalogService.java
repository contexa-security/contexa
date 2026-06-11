package io.contexa.contexaiam.admin.verification.service.resource;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.repository.PromptQualityCertificateLedgerRepository;
import io.contexa.contexacore.repository.ProtectableResourceRegistryRepository;
import io.contexa.contexacore.saas.domain.entity.PromptQualityCertificateLedgerRecord;
import io.contexa.contexacore.saas.domain.entity.ProtectableResourceRegistryRecord;
import io.contexa.contexaiam.admin.verification.service.resource.PromptQualityCertificateService.CertificateScope;
import io.contexa.contexaiam.admin.verification.service.resource.PromptQualityCertificateService.PromptQualityCertificateState;
import io.contexa.contexaiam.admin.verification.service.resource.PromptQualityCertificateService.ProtectableResourceOperationalState;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

@Transactional(transactionManager = "contexaTransactionManager")
public class ProtectableResourceCatalogService {

    private static final String DEFAULT_TENANT_ID = "default";
    private static final String DEFAULT_PROMPT_CONTRACT_VERSION = "official-prompt-contract-v1";
    private static final String DEFAULT_MODEL_PROFILE = "default-model-profile";
    private static final String DEFAULT_VERIFIER_VERSION = "official-verifier-v1";

    private final ListableBeanFactory beanFactory;
    private final ProtectableResourceRegistryRepository registryRepository;
    private final PromptQualityCertificateLedgerRepository ledgerRepository;
    private final PromptQualityCertificateAuditService auditService;
    private final ProtectableResourceOverlayService overlayService;
    private volatile List<ProtectableResourceDescriptor> cachedDescriptors;

    public ProtectableResourceCatalogService(ListableBeanFactory beanFactory) {
        this(
                beanFactory,
                (ProtectableResourceRegistryRepository) null,
                (PromptQualityCertificateLedgerRepository) null,
                (PromptQualityCertificateAuditService) null,
                (ProtectableResourceOverlayService) null
        );
    }

    @Autowired
    public ProtectableResourceCatalogService(
            ListableBeanFactory beanFactory,
            ObjectProvider<ProtectableResourceRegistryRepository> registryRepositoryProvider,
            ObjectProvider<PromptQualityCertificateLedgerRepository> ledgerRepositoryProvider,
            ObjectProvider<PromptQualityCertificateAuditService> auditServiceProvider,
            ObjectProvider<ProtectableResourceOverlayService> overlayServiceProvider) {
        this(
                beanFactory,
                registryRepositoryProvider != null ? registryRepositoryProvider.getIfAvailable() : null,
                ledgerRepositoryProvider != null ? ledgerRepositoryProvider.getIfAvailable() : null,
                auditServiceProvider != null ? auditServiceProvider.getIfAvailable() : null,
                overlayServiceProvider != null ? overlayServiceProvider.getIfAvailable() : null
        );
    }

    ProtectableResourceCatalogService(
            ListableBeanFactory beanFactory,
            ProtectableResourceRegistryRepository registryRepository
    ) {
        this(beanFactory, registryRepository, null, null, null);
    }

    ProtectableResourceCatalogService(
            ListableBeanFactory beanFactory,
            ProtectableResourceRegistryRepository registryRepository,
            PromptQualityCertificateLedgerRepository ledgerRepository,
            PromptQualityCertificateAuditService auditService,
            ProtectableResourceOverlayService overlayService
    ) {
        this.beanFactory = beanFactory;
        this.registryRepository = registryRepository;
        this.ledgerRepository = ledgerRepository;
        this.auditService = auditService;
        this.overlayService = overlayService;
    }

    public List<ProtectableResourceDescriptor> allResources() {
        List<ProtectableResourceDescriptor> descriptors = cachedDescriptors;
        if (descriptors == null) {
            descriptors = refreshResources();
            cachedDescriptors = descriptors;
        }
        return descriptors;
    }

    public List<ProtectableResourceDescriptor> refreshResources() {
        List<ProtectableResourceDescriptor> descriptors = syncRegistry(scanProtectableResources());
        cachedDescriptors = descriptors;
        return descriptors;
    }

    public Optional<ProtectableResourceDescriptor> findBestMatch(
            String requestPath,
            String resourceId,
            String endpointKey,
            String httpMethod
    ) {
        String normalizedPath = normalizePath(requestPath);
        String normalizedMethod = normalizeMethod(httpMethod);
        return allResources().stream()
                .filter(descriptor -> methodMatches(descriptor.httpMethod(), normalizedMethod))
                .filter(descriptor -> pathMatches(descriptor.resourceUrl(), normalizedPath)
                        || resourceMatches(descriptor.resourceId(), resourceId)
                        || endpointMatches(descriptor, endpointKey))
                .max(Comparator.comparingInt(descriptor -> matchScore(descriptor, normalizedPath, resourceId, endpointKey, normalizedMethod)));
    }

    public Optional<ProtectableResourceDescriptor> applyVerificationAttributes(
            HttpServletRequest request,
            String requestPath,
            String resourceId,
            String endpointKey,
            String httpMethod
    ) {
        Optional<ProtectableResourceDescriptor> descriptor = findBestMatch(requestPath, resourceId, endpointKey, httpMethod);
        if (request == null) {
            return descriptor;
        }
        if (descriptor.isEmpty()) {
            request.setAttribute("officialVerification.protectableDeclared", "false");
            return descriptor;
        }
        ProtectableResourceDescriptor value = descriptor.get();
        request.setAttribute("officialVerification.protectableDeclared", "true");
        request.setAttribute("officialVerification.protectableResourceId", value.resourceId());
        request.setAttribute("officialVerification.protectableResourceUrl", value.resourceUrl());
        request.setAttribute("officialVerification.protectableHttpMethod", value.httpMethod());
        request.setAttribute("officialVerification.protectableMethod", value.methodIdentifier());
        request.setAttribute("officialVerification.protectableCriticality", value.criticality());
        request.setAttribute("officialVerification.protectableVerificationRequired", Boolean.toString(value.verificationRequired()));
        request.setAttribute("officialVerification.protectableSync", Boolean.toString(value.sync()));
        request.setAttribute("officialVerification.protectableOwnerField", value.ownerField());
        request.setAttribute("officialVerification.protectableAnnotationSignatureHash", value.annotationSignatureHash());
        request.setAttribute("officialVerification.protectableCertificateState", value.certificateState());
        request.setAttribute("officialVerification.protectableOperationalState", value.operationalState());
        request.setAttribute("officialVerification.protectableLatestCertificateId", value.latestCertificateId());
        request.setAttribute("officialVerification.protectableSignatureChanged", Boolean.toString(value.signatureChanged()));
        return descriptor;
    }

    private List<ProtectableResourceDescriptor> scanProtectableResources() {
        List<ProtectableResourceDescriptor> descriptors = new ArrayList<>();
        String[] beanNames = beanFactory.getBeanNamesForType(Object.class, false, false);
        for (String beanName : beanNames) {
            Class<?> type = resolveBeanType(beanName);
            if (type == null || type.getName().startsWith("org.springframework.")) {
                continue;
            }
            Protectable classAnnotation = AnnotationUtils.findAnnotation(type, Protectable.class);
            ReflectionUtils.doWithMethods(type, method -> {
                Protectable methodAnnotation = AnnotationUtils.findAnnotation(method, Protectable.class);
                Protectable effective = methodAnnotation != null ? methodAnnotation : classAnnotation;
                if (effective == null) {
                    return;
                }
                descriptors.add(toDescriptor(beanName, type, method, effective));
            }, method -> !method.isBridge() && !method.isSynthetic());
        }
        descriptors.sort(Comparator.comparing(ProtectableResourceDescriptor::methodIdentifier));
        return List.copyOf(descriptors);
    }

    private Class<?> resolveBeanType(String beanName) {
        try {
            Class<?> type = beanFactory.getType(beanName);
            if (type == null) {
                return null;
            }
            return type;
        }
        catch (RuntimeException ignored) {
            return null;
        }
    }

    private ProtectableResourceDescriptor toDescriptor(String beanName, Class<?> type, Method method, Protectable protectable) {
        String methodIdentifier = type.getName() + "#" + method.getName();
        String resourceId = valueOrDefault(protectable.resourceId(), methodIdentifier);
        String resourceUrl = valueOrDefault(protectable.resourceUrl(), inferMvcPath(type, method));
        String httpMethod = normalizeMethod(valueOrDefault(protectable.httpMethod(), inferMvcMethod(method)));
        String signatureHash = signatureHash(
                DEFAULT_TENANT_ID,
                resourceId,
                resourceUrl,
                httpMethod,
                methodIdentifier,
                protectable.criticality(),
                Boolean.toString(protectable.verificationRequired()),
                Boolean.toString(protectable.sync()),
                protectable.ownerField()
        );
        return new ProtectableResourceDescriptor(
                beanName,
                methodIdentifier,
                resourceId,
                valueOrNull(resourceUrl),
                httpMethod,
                valueOrDefault(protectable.criticality(), "standard"),
                protectable.verificationRequired(),
                protectable.sync(),
                valueOrNull(protectable.ownerField()),
                type.getName(),
                method.getName(),
                signatureHash,
                "REVIEW_REQUIRED",
                "PENDING_VERIFICATION",
                null,
                false
        );
    }

    private List<ProtectableResourceDescriptor> syncRegistry(List<ProtectableResourceDescriptor> descriptors) {
        if (registryRepository == null) {
            return descriptors;
        }
        LocalDateTime now = LocalDateTime.now();
        Set<String> seenScopes = new HashSet<>();
        List<ProtectableResourceDescriptor> enriched = new ArrayList<>();
        for (ProtectableResourceDescriptor descriptor : descriptors) {
            String resourceId = valueOrDefault(descriptor.resourceId(), descriptor.methodIdentifier());
            String httpMethod = valueOrDefault(descriptor.httpMethod(), "GET").toUpperCase(Locale.ROOT);
            seenScopes.add(registryScope(resourceId, httpMethod));
            ProtectableResourceRegistryRecord record = registryRepository.findByTenantIdAndResourceIdAndHttpMethod(
                            DEFAULT_TENANT_ID,
                            resourceId,
                            httpMethod
                    )
                    .orElseGet(() -> newRegistryRecord(resourceId, httpMethod, now));
            ProtectableResourceOverlayService.ResolvedOverlay overlay = overlayService != null
                    ? overlayService.findActive(DEFAULT_TENANT_ID, resourceId, descriptor.resourceUrl(), httpMethod, now).orElse(null)
                    : null;
            ProtectableResourceDescriptor effective = applyOverlay(descriptor, overlay);
            boolean signatureChanged = StringUtils.hasText(record.getAnnotationSignatureHash())
                    && !record.getAnnotationSignatureHash().equalsIgnoreCase(descriptor.annotationSignatureHash());
            record.setTenantId(DEFAULT_TENANT_ID);
            record.setResourceId(resourceId);
            record.setResourceUrl(valueOrDefault(effective.resourceUrl(), ""));
            record.setHttpMethod(httpMethod);
            record.setCriticality(effective.criticality());
            record.setVerificationRequired(effective.verificationRequired());
            record.setSyncEnabled(effective.sync());
            record.setOwnerField(effective.ownerField());
            record.setBeanName(descriptor.beanName());
            record.setMethodIdentifier(descriptor.methodIdentifier());
            record.setSourceClassName(descriptor.sourceClassName());
            record.setSourceMethodName(descriptor.sourceMethodName());
            record.setAnnotationSignatureHash(descriptor.annotationSignatureHash());
            record.setRetired(false);
            if (signatureChanged) {
                record.setCertificateState("EXPIRED");
                record.setOperationalState("SUSPENDED");
                record.setSignatureChangedAt(now);
                record.setLatestCertificateId(null);
                expireCertificatesForSignatureChange(record, descriptor, now);
            }
            else if (!StringUtils.hasText(record.getOperationalState())) {
                record.setOperationalState("PENDING_VERIFICATION");
                record.setCertificateState("REVIEW_REQUIRED");
            }
            record.setUpdatedAt(now);
            ProtectableResourceRegistryRecord saved = registryRepository.save(record);
            enriched.add(withRegistryState(effective, saved, signatureChanged));
        }
        retireMissingRegistryRecords(seenScopes, now);
        enriched.sort(Comparator.comparing(ProtectableResourceDescriptor::methodIdentifier));
        return List.copyOf(enriched);
    }

    private ProtectableResourceRegistryRecord newRegistryRecord(String resourceId, String httpMethod, LocalDateTime now) {
        ProtectableResourceRegistryRecord record = new ProtectableResourceRegistryRecord();
        record.setTenantId(DEFAULT_TENANT_ID);
        record.setResourceId(resourceId);
        record.setHttpMethod(httpMethod);
        record.setCertificateState("REVIEW_REQUIRED");
        record.setOperationalState("PENDING_VERIFICATION");
        record.setDiscoveredAt(now);
        record.setUpdatedAt(now);
        return record;
    }

    private void retireMissingRegistryRecords(Set<String> seenScopes, LocalDateTime now) {
        registryRepository.findByTenantIdOrderByResourceUrlAscHttpMethodAsc(DEFAULT_TENANT_ID).stream()
                .filter(record -> !seenScopes.contains(registryScope(record.getResourceId(), record.getHttpMethod())))
                .filter(record -> !record.isRetired())
                .forEach(record -> {
                    record.setRetired(true);
                    record.setCertificateState("REVOKED");
                    record.setOperationalState("RETIRED");
                    record.setLatestCertificateId(null);
                    record.setUpdatedAt(now);
                    revokeCertificatesForRetiredResource(record, now);
                    registryRepository.save(record);
                });
    }

    private void expireCertificatesForSignatureChange(
            ProtectableResourceRegistryRecord registryRecord,
            ProtectableResourceDescriptor descriptor,
            LocalDateTime now
    ) {
        if (ledgerRepository == null || registryRecord == null) {
            auditResourceLifecycle(
                    "RESOURCE_SIGNATURE_CHANGED",
                    null,
                    registryRecord,
                    descriptor,
                    "ISSUED",
                    "EXPIRED",
                    "@Protectable 선언 또는 MVC 매핑이 변경되어 기존 보증서를 만료했습니다."
            );
            return;
        }
        ledgerRepository.findTop20ByTenantIdAndResourceIdAndHttpMethodOrderByRecordedAtDesc(
                        valueOrDefault(registryRecord.getTenantId(), DEFAULT_TENANT_ID),
                        valueOrDefault(registryRecord.getResourceId(), ""),
                        valueOrDefault(registryRecord.getHttpMethod(), "GET").toUpperCase(Locale.ROOT)
                )
                .stream()
                .filter(this::runtimeCertificateCanBeInvalidated)
                .forEach(record -> {
                    String previousState = record.getState();
                    record.setState(PromptQualityCertificateState.EXPIRED.name());
                    record.setStateLabel(PromptQualityCertificateState.EXPIRED.label());
                    record.setUsableForLlmZeroTrust(false);
                    record.setZeroTrustState(ProtectableResourceOperationalState.SUSPENDED.name());
                    record.setZeroTrustStateLabel(ProtectableResourceOperationalState.SUSPENDED.label());
                    record.setResourceOperationalState(ProtectableResourceOperationalState.SUSPENDED.name());
                    record.setResourceOperationalStateLabel(ProtectableResourceOperationalState.SUSPENDED.label());
                    record.setExpiresAt(now);
                    record.setSummary("@Protectable 선언 또는 MVC 매핑 변경으로 보증서가 자동 만료되었습니다.");
                    ledgerRepository.save(record);
                    auditResourceLifecycle(
                            "CERTIFICATE_EXPIRED_BY_RESOURCE_CHANGE",
                            record.getCertificateId(),
                            registryRecord,
                            descriptor,
                            previousState,
                            PromptQualityCertificateState.EXPIRED.name(),
                            "리소스 signature hash 변경 감지: " + valueOrDefault(descriptor.annotationSignatureHash(), "n/a")
                    );
                });
        auditResourceLifecycle(
                "RESOURCE_SIGNATURE_CHANGED",
                null,
                registryRecord,
                descriptor,
                "UNCHANGED",
                "SUSPENDED",
                "@Protectable 선언 또는 MVC 매핑이 변경되어 리소스를 재검증 대기 상태로 전환했습니다."
        );
    }

    private void revokeCertificatesForRetiredResource(ProtectableResourceRegistryRecord registryRecord, LocalDateTime now) {
        if (ledgerRepository == null || registryRecord == null) {
            auditResourceLifecycle(
                    "RESOURCE_RETIRED",
                    null,
                    registryRecord,
                    null,
                    "ACTIVE",
                    "RETIRED",
                    "@Protectable 스캔에서 사라진 리소스를 retired 처리했습니다."
            );
            return;
        }
        ledgerRepository.findTop20ByTenantIdAndResourceIdAndHttpMethodOrderByRecordedAtDesc(
                        valueOrDefault(registryRecord.getTenantId(), DEFAULT_TENANT_ID),
                        valueOrDefault(registryRecord.getResourceId(), ""),
                        valueOrDefault(registryRecord.getHttpMethod(), "GET").toUpperCase(Locale.ROOT)
                )
                .stream()
                .filter(this::runtimeCertificateCanBeInvalidated)
                .forEach(record -> {
                    String previousState = record.getState();
                    record.setState(PromptQualityCertificateState.REVOKED.name());
                    record.setStateLabel(PromptQualityCertificateState.REVOKED.label());
                    record.setUsableForLlmZeroTrust(false);
                    record.setZeroTrustState(ProtectableResourceOperationalState.RETIRED.name());
                    record.setZeroTrustStateLabel(ProtectableResourceOperationalState.RETIRED.label());
                    record.setResourceOperationalState(ProtectableResourceOperationalState.RETIRED.name());
                    record.setResourceOperationalStateLabel(ProtectableResourceOperationalState.RETIRED.label());
                    record.setRevokedAt(now);
                    record.setRevokedBy("protectable-resource-catalog");
                    record.setRevocationReason("@Protectable 스캔에서 리소스가 사라져 보증서를 폐기했습니다.");
                    record.setSummary("@Protectable 리소스가 retired 처리되어 보증서가 자동 폐기되었습니다.");
                    ledgerRepository.save(record);
                    auditResourceLifecycle(
                            "CERTIFICATE_REVOKED_BY_RESOURCE_RETIREMENT",
                            record.getCertificateId(),
                            registryRecord,
                            null,
                            previousState,
                            PromptQualityCertificateState.REVOKED.name(),
                            "@Protectable 스캔에서 리소스가 더 이상 발견되지 않았습니다."
                    );
                });
    }

    private boolean runtimeCertificateCanBeInvalidated(PromptQualityCertificateLedgerRecord record) {
        if (record == null) {
            return false;
        }
        return !"EXPIRED".equalsIgnoreCase(record.getState()) && !"REVOKED".equalsIgnoreCase(record.getState());
    }

    private void auditResourceLifecycle(
            String eventType,
            String certificateId,
            ProtectableResourceRegistryRecord registryRecord,
            ProtectableResourceDescriptor descriptor,
            String previousState,
            String nextState,
            String reason
    ) {
        if (auditService == null || registryRecord == null) {
            return;
        }
        auditService.record(
                eventType,
                "protectable-resource-catalog",
                CertificateScope.of(
                        valueOrDefault(registryRecord.getTenantId(), DEFAULT_TENANT_ID),
                        valueOrDefault(descriptor != null ? descriptor.resourceUrl() : registryRecord.getResourceUrl(), ""),
                        valueOrDefault(registryRecord.getHttpMethod(), "GET"),
                        valueOrDefault(registryRecord.getResourceId(), ""),
                        DEFAULT_PROMPT_CONTRACT_VERSION,
                        DEFAULT_MODEL_PROFILE,
                        DEFAULT_VERIFIER_VERSION
                ),
                certificateId,
                previousState,
                nextState,
                reason
        );
    }

    private String registryScope(String resourceId, String httpMethod) {
        return valueOrDefault(resourceId, "n/a").toLowerCase(Locale.ROOT)
                + "|"
                + valueOrDefault(httpMethod, "GET").toUpperCase(Locale.ROOT);
    }

    private ProtectableResourceDescriptor withRegistryState(
            ProtectableResourceDescriptor descriptor,
            ProtectableResourceRegistryRecord record,
            boolean signatureChanged
    ) {
        return new ProtectableResourceDescriptor(
                descriptor.beanName(),
                descriptor.methodIdentifier(),
                descriptor.resourceId(),
                descriptor.resourceUrl(),
                descriptor.httpMethod(),
                descriptor.criticality(),
                descriptor.verificationRequired(),
                descriptor.sync(),
                descriptor.ownerField(),
                descriptor.sourceClassName(),
                descriptor.sourceMethodName(),
                descriptor.annotationSignatureHash(),
                record.getCertificateState(),
                record.getOperationalState(),
                record.getLatestCertificateId(),
                signatureChanged
        );
    }

    private ProtectableResourceDescriptor applyOverlay(
            ProtectableResourceDescriptor descriptor,
            ProtectableResourceOverlayService.ResolvedOverlay overlay
    ) {
        if (overlay == null) {
            return descriptor;
        }
        String mergedResourceUrl = overlay.overlayResourceUrl() != null
                ? overlay.overlayResourceUrl() : descriptor.resourceUrl();
        String mergedCriticality = overlay.overlayCriticality() != null
                ? overlay.overlayCriticality() : descriptor.criticality();
        boolean mergedVerificationRequired = overlay.overlayVerificationRequired() != null
                ? overlay.overlayVerificationRequired() : descriptor.verificationRequired();
        boolean mergedSync = overlay.overlaySync() != null
                ? overlay.overlaySync() : descriptor.sync();
        String mergedOwnerField = overlay.overlayOwnerField() != null
                ? overlay.overlayOwnerField() : descriptor.ownerField();
        return new ProtectableResourceDescriptor(
                descriptor.beanName(),
                descriptor.methodIdentifier(),
                descriptor.resourceId(),
                mergedResourceUrl,
                descriptor.httpMethod(),
                mergedCriticality,
                mergedVerificationRequired,
                mergedSync,
                mergedOwnerField,
                descriptor.sourceClassName(),
                descriptor.sourceMethodName(),
                descriptor.annotationSignatureHash(),
                descriptor.certificateState(),
                descriptor.operationalState(),
                descriptor.latestCertificateId(),
                descriptor.signatureChanged()
        );
    }

    private boolean methodMatches(String declaredMethod, String requestedMethod) {
        if (!StringUtils.hasText(declaredMethod)) {
            return true;
        }
        if (!StringUtils.hasText(requestedMethod)) {
            return true;
        }
        return declaredMethod.equalsIgnoreCase(requestedMethod);
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

    private boolean resourceMatches(String declaredResourceId, String requestedResourceId) {
        if (!StringUtils.hasText(declaredResourceId) || !StringUtils.hasText(requestedResourceId)) {
            return false;
        }
        String declared = declaredResourceId.trim().toLowerCase(Locale.ROOT);
        String requested = requestedResourceId.trim().toLowerCase(Locale.ROOT);
        return declared.equals(requested) || declared.contains("{resourceid}") || declared.endsWith("." + requested);
    }

    private boolean endpointMatches(ProtectableResourceDescriptor descriptor, String endpointKey) {
        if (!StringUtils.hasText(endpointKey)) {
            return false;
        }
        String normalizedEndpoint = endpointKey.trim().toLowerCase(Locale.ROOT);
        return containsIgnoreCase(descriptor.resourceId(), normalizedEndpoint)
                || containsIgnoreCase(descriptor.resourceUrl(), "/" + normalizedEndpoint + "/")
                || containsIgnoreCase(descriptor.criticality(), normalizedEndpoint);
    }

    private int matchScore(
            ProtectableResourceDescriptor descriptor,
            String requestPath,
            String resourceId,
            String endpointKey,
            String httpMethod
    ) {
        int score = 0;
        if (methodMatches(descriptor.httpMethod(), httpMethod) && StringUtils.hasText(descriptor.httpMethod())) {
            score += 3;
        }
        if (pathMatches(descriptor.resourceUrl(), requestPath)) {
            score += 10;
        }
        if (resourceMatches(descriptor.resourceId(), resourceId)) {
            score += 5;
        }
        if (endpointMatches(descriptor, endpointKey)) {
            score += 2;
        }
        return score;
    }

    private boolean containsIgnoreCase(String source, String token) {
        return StringUtils.hasText(source)
                && StringUtils.hasText(token)
                && source.toLowerCase(Locale.ROOT).contains(token.toLowerCase(Locale.ROOT));
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

    private String normalizeMethod(String value) {
        return StringUtils.hasText(value) ? value.trim().toUpperCase(Locale.ROOT) : null;
    }

    private String inferMvcPath(Class<?> type, Method method) {
        String classPath = firstMappingPath(AnnotationUtils.findAnnotation(type, RequestMapping.class));
        String methodPath = firstMethodPath(method);
        if (!StringUtils.hasText(classPath) && !StringUtils.hasText(methodPath)) {
            return null;
        }
        return normalizePath(("/" + valueOrDefault(classPath, "") + "/" + valueOrDefault(methodPath, "")).replaceAll("/{2,}", "/"));
    }

    private String inferMvcMethod(Method method) {
        RequestMethod requestMethod = firstRequestMethod(method);
        return requestMethod != null ? requestMethod.name() : null;
    }

    private String firstMappingPath(RequestMapping mapping) {
        if (mapping == null) {
            return null;
        }
        if (mapping.path().length > 0) {
            return mapping.path()[0];
        }
        if (mapping.value().length > 0) {
            return mapping.value()[0];
        }
        return null;
    }

    private String firstMethodPath(Method method) {
        RequestMapping requestMapping = AnnotationUtils.findAnnotation(method, RequestMapping.class);
        String path = firstMappingPath(requestMapping);
        if (StringUtils.hasText(path)) {
            return path;
        }
        GetMapping getMapping = AnnotationUtils.findAnnotation(method, GetMapping.class);
        path = firstPath(getMapping != null ? getMapping.path() : null, getMapping != null ? getMapping.value() : null);
        if (StringUtils.hasText(path)) {
            return path;
        }
        PostMapping postMapping = AnnotationUtils.findAnnotation(method, PostMapping.class);
        path = firstPath(postMapping != null ? postMapping.path() : null, postMapping != null ? postMapping.value() : null);
        if (StringUtils.hasText(path)) {
            return path;
        }
        PutMapping putMapping = AnnotationUtils.findAnnotation(method, PutMapping.class);
        path = firstPath(putMapping != null ? putMapping.path() : null, putMapping != null ? putMapping.value() : null);
        if (StringUtils.hasText(path)) {
            return path;
        }
        PatchMapping patchMapping = AnnotationUtils.findAnnotation(method, PatchMapping.class);
        path = firstPath(patchMapping != null ? patchMapping.path() : null, patchMapping != null ? patchMapping.value() : null);
        if (StringUtils.hasText(path)) {
            return path;
        }
        DeleteMapping deleteMapping = AnnotationUtils.findAnnotation(method, DeleteMapping.class);
        return firstPath(deleteMapping != null ? deleteMapping.path() : null, deleteMapping != null ? deleteMapping.value() : null);
    }

    private RequestMethod firstRequestMethod(Method method) {
        RequestMapping requestMapping = AnnotationUtils.findAnnotation(method, RequestMapping.class);
        if (requestMapping != null && requestMapping.method().length > 0) {
            return requestMapping.method()[0];
        }
        if (AnnotationUtils.findAnnotation(method, GetMapping.class) != null) {
            return RequestMethod.GET;
        }
        if (AnnotationUtils.findAnnotation(method, PostMapping.class) != null) {
            return RequestMethod.POST;
        }
        if (AnnotationUtils.findAnnotation(method, PutMapping.class) != null) {
            return RequestMethod.PUT;
        }
        if (AnnotationUtils.findAnnotation(method, PatchMapping.class) != null) {
            return RequestMethod.PATCH;
        }
        if (AnnotationUtils.findAnnotation(method, DeleteMapping.class) != null) {
            return RequestMethod.DELETE;
        }
        return null;
    }

    private String firstPath(String[] path, String[] value) {
        if (path != null && path.length > 0) {
            return path[0];
        }
        if (value != null && value.length > 0) {
            return value[0];
        }
        return null;
    }

    private String signatureHash(String... values) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String material = values == null
                    ? ""
                    : String.join("|", java.util.Arrays.stream(values)
                    .map(value -> valueOrDefault(value, ""))
                    .toList());
            return HexFormat.of().formatHex(digest.digest(material.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available.", exception);
        }
    }

    private String valueOrNull(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }

    private String valueOrDefault(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    public record ProtectableResourceDescriptor(
            String beanName,
            String methodIdentifier,
            String resourceId,
            String resourceUrl,
            String httpMethod,
            String criticality,
            boolean verificationRequired,
            boolean sync,
            String ownerField,
            String sourceClassName,
            String sourceMethodName,
            String annotationSignatureHash,
            String certificateState,
            String operationalState,
            String latestCertificateId,
            boolean signatureChanged) {

        public ProtectableResourceDescriptor(
                String beanName,
                String methodIdentifier,
                String resourceId,
                String resourceUrl,
                String httpMethod,
                String criticality,
                boolean verificationRequired,
                boolean sync,
                String ownerField
        ) {
            this(
                    beanName,
                    methodIdentifier,
                    resourceId,
                    resourceUrl,
                    httpMethod,
                    criticality,
                    verificationRequired,
                    sync,
                    ownerField,
                    null,
                    null,
                    null,
                    "REVIEW_REQUIRED",
                    "PENDING_VERIFICATION",
                    null,
                    false
            );
        }
    }
}
