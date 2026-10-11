package io.contexa.contexaiam.admin.promptquality.official.application;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.governance.PromptGovernanceTestSchema;
import io.contexa.contexaiam.testsupport.PromptQualityTestResolvers;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;

import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElement;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElementState;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleManifest;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeGovernanceDescriptorVerificationResult;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.jdbc.core.JdbcTemplate;
import static org.assertj.core.api.Assertions.assertThat;

class JdbcPromptRuntimeGovernanceDescriptorVerifierTest {

    private PostgresTestDatabase database;
    private JdbcTemplate jdbcTemplate;
    private PromptQualityMessageResolver messageResolver;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        jdbcTemplate = database.jdbcTemplate();
        PromptGovernanceTestSchema.apply(jdbcTemplate);
        // The resolver reads the locale of the current context when it resolves, so a test can switch it.
        messageResolver = PromptQualityTestResolvers.koreanBundle();
        LocaleContextHolder.setLocale(Locale.KOREAN);
    }

    @AfterEach
    void tearDown() {
        database.close();
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    void passesOnlyWhenDescriptorMatchesActiveRuntimeRelease() {
        insertRelease("2026.04.27", "hash-active", "PRODUCTION", "approval-001");
        JdbcPromptRuntimeGovernanceDescriptorVerifier verifier =
                new JdbcPromptRuntimeGovernanceDescriptorVerifier(jdbcTemplate, messageResolver);

        RuntimeGovernanceDescriptorVerificationResult result = verifier.verify(packageStub(), Map.of(
                "governanceDescriptor", Map.of(
                        "registryScope", "PLATFORM_GLOBAL",
                        "promptKey", "zt-runtime",
                        "templateKey", "zt-template",
                        "promptVersion", "2026.04.27",
                        "contractVersion", "v1",
                        "promptArtifactHashSha256", "hash-active"
                )));

        assertThat(result.passed()).isTrue();
        assertThat(result.checks()).allSatisfy(check -> assertThat(check.pass()).isTrue());
    }

    @Test
    void blocksStaleDescriptorEvenWhenStaleVersionExistsInRegistry() {
        insertRelease("2026.04.26", "hash-stale", "RETIRED", "approval-old");
        insertRelease("2026.04.27", "hash-active", "PRODUCTION", "approval-001");
        JdbcPromptRuntimeGovernanceDescriptorVerifier verifier =
                new JdbcPromptRuntimeGovernanceDescriptorVerifier(jdbcTemplate, messageResolver);

        RuntimeGovernanceDescriptorVerificationResult result = verifier.verify(packageStub(), Map.of(
                "governanceDescriptor", Map.of(
                        "registryScope", "PLATFORM_GLOBAL",
                        "promptKey", "zt-runtime",
                        "templateKey", "zt-template",
                        "promptVersion", "2026.04.26",
                        "contractVersion", "v1",
                        "promptArtifactHashSha256", "hash-stale"
                )));

        assertThat(result.passed()).isFalse();
        assertThat(result.findings()).anySatisfy(finding ->
                assertThat(finding).contains("프롬프트 버전", "promptGovernance.promptVersion"));
    }

    @Test
    void blocksActiveReleaseWithoutApprovalReference() {
        insertRelease("2026.04.27", "hash-active", "PRODUCTION", null);
        JdbcPromptRuntimeGovernanceDescriptorVerifier verifier =
                new JdbcPromptRuntimeGovernanceDescriptorVerifier(jdbcTemplate, messageResolver);

        RuntimeGovernanceDescriptorVerificationResult result = verifier.verify(packageStub(), Map.of(
                "governanceDescriptor", Map.of(
                        "registryScope", "PLATFORM_GLOBAL",
                        "promptKey", "zt-runtime",
                        "templateKey", "zt-template",
                        "promptVersion", "2026.04.27",
                        "contractVersion", "v1",
                        "promptArtifactHashSha256", "hash-active"
                )));

        assertThat(result.passed()).isFalse();
        assertThat(result.findings()).anySatisfy(finding ->
                assertThat(finding).contains("승인 참조", "promptGovernance.releaseApprovalReference"));
    }

    @Test
    void localizesGovernanceFindingsForEnglishLocale() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        insertRelease("2026.04.27", "hash-active", "PRODUCTION", null);
        JdbcPromptRuntimeGovernanceDescriptorVerifier verifier =
                new JdbcPromptRuntimeGovernanceDescriptorVerifier(jdbcTemplate, messageResolver);

        RuntimeGovernanceDescriptorVerificationResult result = verifier.verify(packageStub(), Map.of(
                "governanceDescriptor", Map.of(
                        "registryScope", "PLATFORM_GLOBAL",
                        "promptKey", "zt-runtime",
                        "templateKey", "zt-template",
                        "promptVersion", "2026.04.27",
                        "contractVersion", "v1",
                        "promptArtifactHashSha256", "hash-active")));

        assertThat(result.findings()).anySatisfy(finding -> assertThat(finding)
                .contains("Prompt Integrated Management issue", "approval reference"));
        assertThat(result.nextActions()).containsExactly(
                "Approve the Prompt Integrated Management release in the core ledger, refresh the runtime cache, and request the protected resource again.");
    }

    @Test
    void aRegistryVersionOutsideTheBuildIsNeverTheActiveRelease() {
        // A problem resolution candidate recorded as a registry row before W1-19 and released for a scope: newer and
        // canary-preferred, but not a bundle of the build, so it cannot be what runs (version management PV-15).
        insertRelease("2026.04.27", "hash-active", "ACTIVE", "approval-001");
        insertRelease("pqa-0123456789ab", "hash-candidate", "ACTIVE_FOR_SCOPE", "PQA-SCOPE-RELEASE:candidate");
        Map<String, Object> metadata = Map.of(
                "governanceDescriptor", Map.of(
                        "registryScope", "PLATFORM_GLOBAL",
                        "promptKey", "zt-runtime",
                        "templateKey", "zt-template",
                        "promptVersion", "2026.04.27",
                        "contractVersion", "v1",
                        "promptArtifactHashSha256", "hash-active"));

        RuntimeGovernanceDescriptorVerificationResult withBuild = new JdbcPromptRuntimeGovernanceDescriptorVerifier(
                jdbcTemplate, messageResolver, new PromptBundleCatalog(List.of(manifest("zt-runtime", "2026.04.27"))))
                .verify(packageStub(), metadata);
        RuntimeGovernanceDescriptorVerificationResult withoutBundles = new JdbcPromptRuntimeGovernanceDescriptorVerifier(
                jdbcTemplate, messageResolver, new PromptBundleCatalog(List.of()))
                .verify(packageStub(), metadata);

        assertThat(withBuild.passed()).isTrue();
        // A prompt key without bundles in the build keeps the registry order, where the scoped row comes first.
        assertThat(withoutBundles.passed()).isFalse();
        assertThat(withoutBundles.findings()).anySatisfy(finding ->
                assertThat(finding).contains("promptGovernance.promptVersion"));
    }

    private static PromptBundleManifest manifest(String promptKey, String bundleVersion) {
        List<PromptBundleElement> elements = new ArrayList<>();
        for (String id : PromptBundleHashes.ELEMENT_IDS) {
            elements.add("B1".equals(id)
                    ? PromptBundleHashes.present(id, "system text of " + bundleVersion, "text")
                    : PromptBundleHashes.marker(id, PromptBundleElementState.ABSENT, "none"));
        }
        return new PromptBundleManifest(promptKey, bundleVersion, PromptBundleHashes.bundleHash(elements), elements,
                null, null, "summary", List.of(), "author", "2026-10-10", null, List.of(), List.of(), List.of());
    }

    private void insertRelease(String promptVersion, String artifactHash, String releaseStatus, String approvalReference) {
        jdbcTemplate.update(
                """
                        insert into prompt_governance_registry (
                            registry_scope, prompt_key, template_key, prompt_version,
                            contract_version, prompt_artifact_hash_sha256, release_status,
                            owner_name, release_approval_reference, evaluation_baseline_reference,
                            rollback_prompt_version, change_summary, template_class_name,
                            registration_source, supported_model_profiles_json, created_at, updated_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, current_timestamp, current_timestamp)
                        """,
                "PLATFORM_GLOBAL",
                "zt-runtime",
                "zt-template",
                promptVersion,
                "v1",
                artifactHash,
                releaseStatus,
                "pqa",
                approvalReference,
                "PQA-PORTFOLIO-PASSED:test",
                "rollback-version",
                "test release",
                "io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate",
                "test",
                "[\"MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI\"]");
    }

    private SealedEvidencePackage packageStub() {
        return SealedEvidencePackage.builder()
                .packageId("sep-001")
                .build();
    }
}
