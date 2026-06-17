package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class PromptQualityCertificateService implements PromptQualityRuntimeCertificateIssuer {

    private static final ZoneId KOREA_ZONE = ZoneId.of("Asia/Seoul");
    private static final String DEFAULT_TENANT_ID = "default";
    private static final String DEFAULT_PROMPT_CONTRACT_VERSION = "official-prompt-contract-v1";
    private static final String DEFAULT_MODEL_PROFILE = "default-model-profile";
    private static final String DEFAULT_VERIFIER_VERSION = "official-verifier-v1";
    private static final String EVIDENCE_SOURCE_SEALED_RUNTIME_PACKAGE = "SEALED_RUNTIME_PACKAGE";

    private final Map<String, PromptQualityCertificate> latestByPackageId = new ConcurrentHashMap<>();
    private final Map<String, PromptQualityCertificate> latestByScopeHash = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<PromptQualityCertificate> recentCertificates = new CopyOnWriteArrayList<>();

    public PromptQualityCertificate issue(
            String generatedAt,
            String userId,
            String resourceUrl,
            String resourceId,
            String httpMethod,
            ProtectableResourceDescriptor descriptor,
            List<MetricRunEvidence> evidence,
            List<MetricExecutionFailure> failures) {
        CertificateScope scope = CertificateScope.of(
                DEFAULT_TENANT_ID,
                resourceUrl,
                httpMethod,
                resourceId,
                DEFAULT_PROMPT_CONTRACT_VERSION,
                DEFAULT_MODEL_PROFILE,
                DEFAULT_VERIFIER_VERSION);
        return issue(generatedAt, userId, scope, descriptor, evidence, failures);
    }

    @Override
    public PromptQualityCertificate issue(
            String generatedAt,
            String userId,
            CertificateScope scope,
            ProtectableResourceDescriptor descriptor,
            List<MetricRunEvidence> evidence,
            List<MetricExecutionFailure> failures) {
        List<MetricRunEvidence> safeEvidence = evidence == null ? List.of() : evidence;
        List<MetricExecutionFailure> safeFailures = failures == null ? List.of() : failures;
        int total = safeEvidence.size();
        int verified = (int) safeEvidence.stream().filter(item -> runPassed(item.run())).count();
        int failed = safeFailures.size() + (int) safeEvidence.stream().filter(item -> !runPassed(item.run())).count();
        int missing = Math.max(0, 12 - total);
        boolean protectablePresent = descriptor != null;
        boolean verificationRequired = descriptor == null || descriptor.verificationRequired();
        boolean issued = protectablePresent && verificationRequired && total >= 12 && failed == 0 && missing == 0;
        String state = issued ? "ISSUED" : "BLOCKED";
        List<String> blockingFindings = new ArrayList<>();
        if (!protectablePresent) {
            blockingFindings.add("보호 리소스 등록 정보를 확인해야 합니다.");
        }
        if (!verificationRequired) {
            blockingFindings.add("품질 보증 대상 리소스가 아닙니다.");
        }
        if (failed > 0) {
            blockingFindings.add("통과하지 못한 공식검사 지표가 있습니다.");
        }
        if (missing > 0) {
            blockingFindings.add("공식검사 지표 결과가 부족합니다.");
        }
        List<String> recommendedActions = blockingFindings.isEmpty()
                ? List.of("공식검사 결과를 기준으로 운영 승격 단계를 진행하십시오.")
                : List.copyOf(blockingFindings);
        String packageId = packageId(safeEvidence);
        PromptQualityCertificate certificate = new PromptQualityCertificate(
                "pqc-" + UUID.randomUUID(),
                scope,
                state,
                issued ? "품질 보증서 발급" : "품질 보증서 발급 차단",
                issued,
                issued ? "CERTIFIED" : "BLOCKED",
                issued ? "보증 완료" : "제로트러스트 차단",
                issued ? "CERTIFIED" : "BLOCKED",
                issued ? "보증 완료" : "제로트러스트 차단",
                issued ? valueOrDefault(generatedAt, LocalDateTime.now(KOREA_ZONE).toString()) : null,
                null,
                null,
                null,
                null,
                packageId,
                EVIDENCE_SOURCE_SEALED_RUNTIME_PACKAGE,
                evidenceHash(safeEvidence, "prompt"),
                evidenceHash(safeEvidence, "system"),
                evidenceHash(safeEvidence, "user"),
                evidenceHash(safeEvidence, "decision"),
                evidenceHash(safeEvidence, "prompt"),
                evidenceHash(safeEvidence, "system"),
                evidenceHash(safeEvidence, "user"),
                evidenceHash(safeEvidence, "context"),
                requestIds(safeEvidence),
                runIds(safeEvidence),
                scope == null ? null : scope.resourceUrl(),
                scope == null ? null : scope.protectableResourceId(),
                scope == null ? null : scope.httpMethod(),
                descriptor == null ? null : descriptor.methodIdentifier(),
                descriptor == null ? null : descriptor.criticality(),
                verificationRequired,
                total,
                verified,
                failed,
                missing,
                List.copyOf(blockingFindings),
                issued ? "공식검사 기준을 충족했습니다." : "공식검사 기준을 충족하지 못했습니다.",
                new SixWReport(valueOrDefault(generatedAt, ""), valueOrDefault(scope == null ? null : scope.resourceUrl(), ""), valueOrDefault(userId, ""), "PQA official verification", "official inspection", "prompt quality assurance", state),
                null,
                null,
                null,
                List.of(),
                recommendedActions);
        remember(certificate);
        return certificate;
    }

    public List<PromptQualityCertificate> recentCertificates() {
        return List.copyOf(recentCertificates);
    }

    public PromptQualityCertificate findLatestBySealedEvidencePackageId(String packageId) {
        return StringUtils.hasText(packageId) ? latestByPackageId.get(packageId.trim()) : null;
    }

    private void remember(PromptQualityCertificate certificate) {
        if (certificate == null) {
            return;
        }
        recentCertificates.add(0, certificate);
        if (certificate.scope() != null) {
            latestByScopeHash.put(certificate.scope().scopeHash(), certificate);
        }
        if (StringUtils.hasText(certificate.sealedEvidencePackageId())) {
            latestByPackageId.put(certificate.sealedEvidencePackageId(), certificate);
        }
    }

    private boolean runPassed(OfficialVerificationRunView run) {
        if (run == null || !StringUtils.hasText(run.state())) {
            return false;
        }
        String normalized = run.state().trim().toUpperCase(Locale.ROOT);
        return normalized.equals("SUCCESS") || normalized.equals("PASS") || normalized.equals("PASSED")
                || normalized.equals("VERIFIED") || normalized.equals("COMPLETED")
                || normalized.contains("THRESHOLD PASSED");
    }

    private String packageId(List<MetricRunEvidence> evidence) {
        for (MetricRunEvidence item : evidence) {
            OfficialVerificationRunView run = item == null ? null : item.run();
            Map<String, Object> raw = run == null ? null : run.rawEvidence();
            String value = raw == null || raw.get("packageId") == null ? null : String.valueOf(raw.get("packageId"));
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private List<String> requestIds(List<MetricRunEvidence> evidence) {
        return evidence.stream()
                .map(MetricRunEvidence::run)
                .filter(run -> run != null && run.rawEvidence() != null)
                .map(run -> run.rawEvidence().get("requestId"))
                .map(value -> value == null ? null : String.valueOf(value))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private List<String> runIds(List<MetricRunEvidence> evidence) {
        return evidence.stream()
                .map(MetricRunEvidence::run)
                .filter(run -> run != null && StringUtils.hasText(run.runId()))
                .map(OfficialVerificationRunView::runId)
                .distinct()
                .toList();
    }

    private String evidenceHash(List<MetricRunEvidence> evidence, String salt) {
        String material = salt + "|" + evidence.stream()
                .map(item -> item.run() == null ? item.metricCode() : item.run().runId())
                .toList();
        return sha256(material);
    }

    private String sha256(String material) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return "sha256:" + HexFormat.of().formatHex(digest.digest(valueOrDefault(material, "").getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available.", exception);
        }
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
                String verifierVersion) {
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
                    normalizedVerifier);
            return new CertificateScope(
                    normalizedTenant,
                    normalizedUrl,
                    normalizedMethod,
                    normalizedResource,
                    normalizedPromptContract,
                    normalizedModel,
                    normalizedVerifier,
                    sha256Static(material));
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

        private static String sha256Static(String material) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                return HexFormat.of().formatHex(digest.digest(material.getBytes(StandardCharsets.UTF_8)));
            }
            catch (NoSuchAlgorithmException exception) {
                throw new IllegalStateException("SHA-256 is not available.", exception);
            }
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
            return usableForLlmZeroTrust && "ISSUED".equalsIgnoreCase(state);
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

    public record PromptQualityIssueCase(String caseId) {
    }

    public record EvidenceLineage(Map<String, Object> values) {
        public EvidenceLineage {
            values = values == null ? Map.of() : new LinkedHashMap<>(values);
        }
    }

    public record RemediationLoop(String state) {
    }

    public record MetricCertificateItem(String metricCode, String state, boolean verified) {
    }
}
