package io.contexa.contexaiam.admin.verification.service.resource;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.repository.ProtectableResourceRegistryRepository;
import io.contexa.contexacore.saas.domain.entity.ProtectableResourceRegistryRecord;
import io.contexa.contexaiam.security.xacml.pep.ProtectableResourceCertificationGate;
import io.contexa.contexaiam.admin.verification.service.resource.PromptQualityCertificateService.CertificateScope;
import io.contexa.contexaiam.admin.verification.service.resource.PromptQualityCertificateService.PromptQualityCertificate;
import jakarta.servlet.http.HttpServletRequest;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Locale;

public class EnterpriseProtectableResourceCertificationGate implements ProtectableResourceCertificationGate {

    private final PromptQualityCertificateService promptQualityCertificateService;
    private final PromptQualityCertificateAuditService auditService;
    private final ProtectableResourceRegistryRepository registryRepository;
    private final RuntimeCertificateEnforcementMode enforcementMode;

    public EnterpriseProtectableResourceCertificationGate(PromptQualityCertificateService promptQualityCertificateService) {
        this(promptQualityCertificateService, null, null, RuntimeCertificateEnforcementMode.BLOCK.name());
    }

    public EnterpriseProtectableResourceCertificationGate(
            PromptQualityCertificateService promptQualityCertificateService,
            String enforcementMode
    ) {
        this(promptQualityCertificateService, null, null, enforcementMode);
    }

    public EnterpriseProtectableResourceCertificationGate(
            PromptQualityCertificateService promptQualityCertificateService,
            ProtectableResourceRegistryRepository registryRepository,
            String enforcementMode
    ) {
        this(promptQualityCertificateService, null, registryRepository, enforcementMode);
    }

    public EnterpriseProtectableResourceCertificationGate(
            PromptQualityCertificateService promptQualityCertificateService,
            PromptQualityCertificateAuditService auditService,
            ProtectableResourceRegistryRepository registryRepository,
            @Value("${contexa.zerotrust.certificate.enforcement-mode:BLOCK}") String enforcementMode
    ) {
        this.promptQualityCertificateService = promptQualityCertificateService;
        this.auditService = auditService;
        this.registryRepository = registryRepository;
        this.enforcementMode = RuntimeCertificateEnforcementMode.from(enforcementMode);
    }

    @Override
    public CertificationDecision evaluate(
            MethodInvocation methodInvocation,
            Authentication authentication,
            Protectable protectable,
            String resourceId) {
        if (protectable == null || !protectable.verificationRequired()) {
            return CertificationDecision.allowed("이 리소스는 품질 보증서 검사가 필요하지 않습니다.");
        }

        HttpServletRequest request = currentRequest();
        String requestPath = request != null ? normalizePath(request.getRequestURI()) : "";
        if (isOfficialVerifierRequest(requestPath)) {
            return CertificationDecision.allowed("공식 검증기 실행 요청은 보증서 발급 전 단계이므로 허용합니다.");
        }

        String effectiveResourceId = valueOrDefault(resourceId, protectable.resourceId());
        String effectiveResourceUrl = valueOrDefault(requestPath, protectable.resourceUrl());
        String requestMethod = request != null ? request.getMethod() : protectable.httpMethod();
        CertificateScope scope = CertificateScope.of(
                resolveTenantId(request),
                effectiveResourceUrl,
                requestMethod,
                effectiveResourceId,
                resolveHeaderOrAttribute(request, "X-Prompt-Contract-Version", "officialVerification.promptContractVersion", null),
                resolveHeaderOrAttribute(request, "X-Model-Profile", "officialVerification.modelProfile", null),
                resolveHeaderOrAttribute(request, "X-Verifier-Version", "officialVerification.verifierVersion", null)
        );
        if (!StringUtils.hasText(effectiveResourceUrl)) {
            CertificationDecision decision = CertificationDecision.blocked(
                    "CERTIFICATE_SCOPE_MISSING",
                    "보호 대상 요청 URL을 확인할 수 없어 품질 보증서를 찾을 수 없습니다."
            );
            auditGate("RESOURCE_GATE_BLOCKED", authentication, scope, null, decision.state(), decision.message());
            return decision;
        }

        PromptQualityCertificate certificate = latestCertificateForRuntime(scope, protectable, requestMethod, effectiveResourceId);
        if (certificate == null) {
            return applyEnforcementPolicy(
                    "CERTIFICATE_MISSING",
                    "이 보호 리소스에 발급된 공식 프롬프트 품질 보증서가 없습니다.",
                    authentication,
                    scope,
                    null
            );
        }
        if (!certificate.currentlyValidForRuntime()) {
            return applyEnforcementPolicy(
                    valueOrDefault(certificate.zeroTrustState(), "CERTIFICATE_BLOCKED"),
                    valueOrDefault(certificate.summary(), "최근 프롬프트 품질 보증서 기준상 이 리소스 실행 전 조치가 필요합니다."),
                    authentication,
                    scope,
                    certificate
            );
        }

        if (StringUtils.hasText(certificate.httpMethod())
                && StringUtils.hasText(requestMethod)
                && !certificate.httpMethod().equalsIgnoreCase(requestMethod)) {
            CertificationDecision decision = CertificationDecision.blocked(
                    "CERTIFICATE_METHOD_MISMATCH",
                    "품질 보증서가 다른 HTTP 메서드로 발급되었습니다."
            );
            auditGate("RESOURCE_GATE_BLOCKED", authentication, scope, certificate, decision.state(), decision.message());
            return decision;
        }

        if (!zeroTrustEnabledForRuntime(scope, certificate)) {
            return applyEnforcementPolicy(
                    "PROMOTION_REQUIRED",
                    "품질 보증서는 발급되었지만 이 리소스의 제로트러스트 운영 승격이 아직 승인되지 않았습니다.",
                    authentication,
                    scope,
                    certificate
            );
        }

        return CertificationDecision.allowed("최근 공식 프롬프트 품질 보증서와 운영 승격 상태가 확인되어 LLM 제로트러스트 실행을 허용합니다.");
    }

    private CertificationDecision applyEnforcementPolicy(
            String state,
            String message,
            Authentication authentication,
            CertificateScope scope,
            PromptQualityCertificate certificate
    ) {
        CertificationDecision decision = switch (enforcementMode) {
            case SHADOW_ONLY -> new CertificationDecision(
                    true,
                    "SHADOW_ONLY",
                    "관찰 모드라 실행은 허용했지만 보증서 게이트 문제를 기록했습니다: " + message
            );
            case PENDING_ANALYSIS -> CertificationDecision.blocked(
                    "PENDING_ANALYSIS",
                    "보증서 게이트가 LLM 제로트러스트 실행 전 검토를 요구합니다: " + message
            );
            case BLOCK -> CertificationDecision.blocked(state, message);
        };
        auditGate(decision.allowed() ? "RESOURCE_GATE_SHADOW_ONLY" : "RESOURCE_GATE_BLOCKED", authentication, scope, certificate, decision.state(), decision.message());
        return decision;
    }

    private void auditGate(
            String eventType,
            Authentication authentication,
            CertificateScope scope,
            PromptQualityCertificate certificate,
            String nextState,
            String reason
    ) {
        if (auditService == null) {
            return;
        }
        auditService.record(
                eventType,
                authentication != null && StringUtils.hasText(authentication.getName()) ? authentication.getName() : "runtime-gate",
                scope,
                certificate != null ? certificate.certificateId() : null,
                certificate != null ? certificate.resourceOperationalState() : null,
                nextState,
                reason
        );
    }

    private PromptQualityCertificate latestCertificateForRuntime(
            CertificateScope primaryScope,
            Protectable protectable,
            String requestMethod,
            String effectiveResourceId
    ) {
        PromptQualityCertificate certificate = promptQualityCertificateService.latestFor(primaryScope);
        if (certificate != null) {
            return certificate;
        }
        if (protectable != null && StringUtils.hasText(protectable.resourceUrl())) {
            certificate = promptQualityCertificateService.latestFor(CertificateScope.of(
                    primaryScope.tenantId(),
                    protectable.resourceUrl(),
                    requestMethod,
                    valueOrDefault(effectiveResourceId, protectable.resourceId()),
                    primaryScope.promptContractVersion(),
                    primaryScope.modelProfile(),
                    primaryScope.verifierVersion()
            ));
            if (certificate != null) {
                return certificate;
            }
        }
        if (protectable != null && StringUtils.hasText(protectable.resourceId())) {
            return promptQualityCertificateService.latestFor(CertificateScope.of(
                    primaryScope.tenantId(),
                    primaryScope.resourceUrl(),
                    requestMethod,
                    protectable.resourceId(),
                    primaryScope.promptContractVersion(),
                    primaryScope.modelProfile(),
                    primaryScope.verifierVersion()
            ));
        }
        return null;
    }

    private boolean zeroTrustEnabledForRuntime(CertificateScope scope, PromptQualityCertificate certificate) {
        String registryState = registryOperationalState(scope);
        if (StringUtils.hasText(registryState)) {
            return "ZERO_TRUST_ENABLED".equalsIgnoreCase(registryState);
        }
        return certificate != null && "ZERO_TRUST_ENABLED".equalsIgnoreCase(certificate.resourceOperationalState());
    }

    private String registryOperationalState(CertificateScope scope) {
        if (registryRepository == null || scope == null) {
            return null;
        }
        String tenantId = valueOrDefault(scope.tenantId(), "default");
        String resourceId = scope.protectableResourceId();
        String httpMethod = normalizeMethod(scope.httpMethod());
        if (!StringUtils.hasText(resourceId) || !StringUtils.hasText(httpMethod)) {
            return null;
        }
        return registryRepository.findByTenantIdAndResourceIdAndHttpMethod(tenantId, resourceId, httpMethod)
                .map(ProtectableResourceRegistryRecord::getOperationalState)
                .orElse(null);
    }

    private HttpServletRequest currentRequest() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            return attributes.getRequest();
        }
        return null;
    }

    private boolean isOfficialVerifierRequest(String requestPath) {
        return StringUtils.hasText(requestPath)
                && requestPath.toLowerCase(Locale.ROOT).startsWith("/admin/api/enterprise/verification");
    }

    private String resolveTenantId(HttpServletRequest request) {
        return valueOrDefault(resolveHeaderOrAttribute(request, "X-Tenant-Id", "tenantId", null), "default");
    }

    private String resolveHeaderOrAttribute(HttpServletRequest request, String headerName, String attributeName, String fallback) {
        if (request == null) {
            return fallback;
        }
        String header = request.getHeader(headerName);
        if (StringUtils.hasText(header)) {
            return header.trim();
        }
        Object attribute = request.getAttribute(attributeName);
        return attribute != null && StringUtils.hasText(attribute.toString()) ? attribute.toString().trim() : fallback;
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

    private String normalizeMethod(String value) {
        return StringUtils.hasText(value) ? value.trim().toUpperCase(Locale.ROOT) : null;
    }

    enum RuntimeCertificateEnforcementMode {
        BLOCK,
        PENDING_ANALYSIS,
        SHADOW_ONLY;

        static RuntimeCertificateEnforcementMode from(String value) {
            if (!StringUtils.hasText(value)) {
                return BLOCK;
            }
            try {
                return RuntimeCertificateEnforcementMode.valueOf(value.trim().toUpperCase(Locale.ROOT));
            } catch (RuntimeException ignored) {
                return BLOCK;
            }
        }
    }
}
