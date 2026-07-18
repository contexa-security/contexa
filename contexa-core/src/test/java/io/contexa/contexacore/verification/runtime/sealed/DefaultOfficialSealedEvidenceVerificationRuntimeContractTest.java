package io.contexa.contexacore.verification.runtime.sealed;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupPort;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePromptEvidenceBackfill;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricCatalog;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunStore;
import io.contexa.contexacore.verification.runtime.testsupport.OfficialVerificationTestMessages;
import io.contexa.contexacore.verification.runtime.sealed.testsupport.OfficialSealedEvidenceVerificationRuntimeContract;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DefaultOfficialSealedEvidenceVerificationRuntimeContractTest
        extends OfficialSealedEvidenceVerificationRuntimeContract {

    @Override
    protected OfficialSealedEvidenceVerificationRuntime runtime() {
        SealedEvidencePackage evidencePackage = completeEvidencePackage();
        SealedEvidencePackageLookupPort lookup = mock(SealedEvidencePackageLookupPort.class);
        when(lookup.findByPackageId(packageId())).thenReturn(Optional.of(evidencePackage));
        when(lookup.verifyIntegrity(any(SealedEvidencePackage.class))).thenReturn(true);
        return new DefaultOfficialSealedEvidenceVerificationRuntime(
                lookup,
                new OfficialVerificationMetricCatalog(),
                new OfficialVerificationRunStore(),
                (userId, record) -> { },
                new ObjectMapper(),
                OfficialVerificationTestMessages.deterministic());
    }

    @Override
    protected String packageId() {
        return "sep-oss-contract-001";
    }

    @Test
    void promptEvidenceBackfillPreparesLegacyPackageWithoutMutatingPersistedEntity() {
        SealedEvidencePackage legacy = completeEvidencePackage();
        legacy.setSystemPromptHash(null);
        legacy.setUserPromptHash(null);
        legacy.setRawSystemPromptHash(null);
        legacy.setRawUserPromptHash(null);
        legacy.setPromptEvidenceManifestJson(null);
        legacy.setSealState(null);
        legacy.setSchemaVersion(1);
        SealedEvidencePackageIntegrity integrity = new SealedEvidencePackageIntegrity();
        legacy.setPackageHash(integrity.computeHash(legacy));

        SealedEvidencePromptEvidenceBackfill.Result result = SealedEvidencePromptEvidenceBackfill.prepare(
                new ObjectMapper(), legacy, OfficialVerificationTestMessages.deterministic());

        assertThat(result.ready()).isTrue();
        assertThat(result.recoveredFields()).contains(
                "systemPromptHash",
                "userPromptHash",
                "rawSystemPromptHash",
                "rawUserPromptHash",
                "promptEvidenceManifestJson",
                "sealState",
                "schemaVersion",
                "packageHash");
        assertThat(result.packageForVerification()).isNotSameAs(legacy);
        assertThat(result.packageForVerification().getPromptEvidenceManifestJson())
                .contains("USER_PROMPT_EVIDENCE_CONTRACT_V1");
        assertThat(result.packageForVerification().getSystemPromptHash()).startsWith("sha256:");
        assertThat(result.packageForVerification().getSchemaVersion()).isEqualTo(2);
        assertThat(integrity.verify(result.packageForVerification())).isTrue();
        assertThat(legacy.getPromptEvidenceManifestJson()).isNull();
        assertThat(legacy.getSystemPromptHash()).isNull();
        assertThat(legacy.getSchemaVersion()).isEqualTo(1);
    }

    private SealedEvidencePackage completeEvidencePackage() {
        String systemPrompt = "system";
        String userPrompt = validUserPrompt();
        String systemPromptHash = prefixedSha256(systemPrompt);
        String userPromptHash = prefixedSha256(userPrompt);
        return SealedEvidencePackage.builder()
                .packageId(packageId())
                .correlationId("corr-oss-contract-001")
                .tenantId("tenant-a")
                .userId("user-a")
                .capturedAt(Instant.parse("2026-04-27T00:00:00Z"))
                .requestFactsJson("""
                        {"tenantId":"tenant-a","clientIp":"127.0.0.1","requestPath":"/api/protected","path":"/api/protected","actualResourceId":"resource-001","resourceId":"resource-001","httpMethod":"GET","requestId":"req-oss-contract-001"}
                        """)
                .authStateJson("""
                        {"mfaVerified":true,"authorizationEffect":"ALLOW","effectiveRoles":["USER"],"authMethod":"MFA","effectivePermissions":["READ"]}
                        """)
                .canonicalContextJson("""
                        {"observedScope":{},"sessionNarrativeProfile":{},"frictionProfile":{}}
                        """)
                .baselineSnapshotJson("""
                        {"isNewUser":false,"isNewDevice":false,"isNewSession":false}
                        """)
                .ragResultsJson("""
                        {"totalDocumentCount":1,"authorizedDocumentCount":1,"deniedDocumentCount":0,"purposeMismatchCount":0,"scopeViolationCount":0,"foreignUserDocumentCount":0,"deniedReasons":[]}
                        """)
                .rawSystemPrompt(systemPrompt)
                .rawUserPrompt(userPrompt)
                .systemPromptText(systemPrompt)
                .userPromptText(userPrompt)
                .promptHash("prompt-hash-oss-contract-001")
                .systemPromptHash(systemPromptHash)
                .userPromptHash(userPromptHash)
                .rawSystemPromptHash(systemPromptHash)
                .rawUserPromptHash(userPromptHash)
                .promptExecutionMetadataJson("""
                        {"promptVersion":"v1","promptHash":"prompt-hash-oss-contract-001","systemPromptHash":"%s","userPromptHash":"%s","rawSystemPromptHash":"%s","rawUserPromptHash":"%s","promptSectionSet":["identity"],"omittedSections":[],"promptEvidenceCompleteness":"FULL","governanceDescriptor":{"templateKey":"zt","promptKey":"zt-v1"}}
                        """.formatted(systemPromptHash, userPromptHash, systemPromptHash, userPromptHash))
                .decisionJson("""
                        {"action":"ALLOW","evidenceRefs":["baseline.status.mature","behavior.matches_baseline","authorization.policy.allow"],"reasoning":"the request matches the mature baseline and the policy permits the request"}
                        """)
                .packageHash("package-hash-oss-contract-001")
                .schemaVersion(1)
                .sealed(true)
                .expiresAt(Instant.parse("2026-04-28T00:00:00Z"))
                .build();
    }

    private String prefixedSha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return "sha256:" + HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private String validUserPrompt() {
        return """
                RequestId: req-oss-contract-001
                TenantId: tenant-a
                HttpMethod: GET
                RequestPath: /api/protected
                ResourceId: resource-001
                ClientIp: 127.0.0.1
                AuthenticationType: MFA
                MfaVerified: true
                AuthorizationEffect: ALLOW
                EffectiveRoles: USER
                EffectivePermissions: READ
                DecisionAction: ALLOW
                """;
    }
}