package io.contexa.site.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacoreenterprise.benchmark.publication.BenchmarkPublicationCoreConfiguration;
import io.contexa.contexacoreenterprise.benchmark.publication.BenchmarkPublicationProperties;
import io.contexa.contexacoreenterprise.benchmark.publication.persistence.PublishedBenchmarkReleaseRecord;
import io.contexa.contexacoreenterprise.benchmark.publication.persistence.PublishedBenchmarkReleaseStore;
import io.contexa.contexacoreenterprise.benchmark.persistence.BenchmarkRunLedgerRecord;
import io.contexa.contexacoreenterprise.verification.metric.OfficialVerificationMetricCatalog;
import io.contexa.contexacoreenterprise.verification.persistence.VerificationRunLedgerRecord;
import io.contexa.site.ContexaSiteApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(
        classes = {
                PublicBenchmarkDatabaseBootstrapTest.TestSiteApplication.class,
                PublicBenchmarkDatabaseBootstrapTest.TestBenchmarkBootstrapConfiguration.class
        },
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.messages.basename=i18n/messages-site,i18n/messages-enterprise,i18n/messages",
                "spring.thymeleaf.cache=false",
                "spring.datasource.url=jdbc:h2:mem:contexa-site-benchmark;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
                "spring.datasource.driver-class-name=org.h2.Driver",
                "spring.datasource.username=sa",
                "spring.datasource.password=",
                "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.flyway.enabled=true",
                "spring.sql.init.mode=never",
                "spring.data.redis.repositories.enabled=false",
                "spring.autoconfigure.exclude=io.contexa.autoconfigure.core.advisor.CoreAdvisorAutoConfiguration,io.contexa.autoconfigure.core.autonomous.CoreAutonomousAutoConfiguration,io.contexa.autoconfigure.core.autonomous.CoreAutonomousEventAutoConfiguration,io.contexa.autoconfigure.core.autonomous.CoreAutonomousStrategyAutoConfiguration,io.contexa.autoconfigure.core.autonomous.CoreSaasForwardingAutoConfiguration,io.contexa.autoconfigure.core.CoreDataAutoConfiguration,io.contexa.autoconfigure.core.hcad.CoreHCADAutoConfiguration,io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration,io.contexa.autoconfigure.core.infra.CoreInfrastructureExtendedAutoConfiguration,io.contexa.autoconfigure.core.llm.CoreLLMAutoConfiguration,io.contexa.autoconfigure.core.llm.CoreLLMTieredAutoConfiguration,io.contexa.autoconfigure.core.rag.CoreRAGAutoConfiguration,io.contexa.autoconfigure.core.session.CoreSessionAutoConfiguration,io.contexa.autoconfigure.core.std.CoreStdComponentsAutoConfiguration,io.contexa.autoconfigure.core.streaming.CoreStreamingAutoConfiguration,io.contexa.autoconfigure.enterprise.dashboard.EnterpriseDashboardAutoConfiguration,io.contexa.autoconfigure.enterprise.iam.IamEnterpriseAutoConfiguration,io.contexa.autoconfigure.enterprise.iam.IamEnterpriseI18nAutoConfiguration,io.contexa.autoconfigure.enterprise.soar.EnterpriseAiNativeOperationsAutoConfiguration,io.contexa.autoconfigure.enterprise.soar.EnterpriseSoarAutoConfiguration,io.contexa.autoconfigure.enterprise.tool.EnterpriseToolAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminAccessCenterAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminAuthAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminBlacklistAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminCenterAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminIpAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminMetadataAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminMonitoringAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminPasswordPolicyAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminSessionAutoConfiguration,io.contexa.autoconfigure.iam.aiam.IamAiamComponentsAutoConfiguration,io.contexa.autoconfigure.iam.aiam.IamAiamInfrastructureAutoConfiguration,io.contexa.autoconfigure.iam.aiam.IamAiamLabsAutoConfiguration,io.contexa.autoconfigure.iam.aiam.IamAiamServiceStrategyAutoConfiguration,io.contexa.autoconfigure.iam.aiam.IamAiamWebAutoConfiguration,io.contexa.autoconfigure.iam.aiam.IamAiamZeroTrustSseAutoConfiguration,io.contexa.autoconfigure.iam.IamI18nAutoConfiguration,io.contexa.autoconfigure.iam.IamInfrastructureAutoConfiguration,io.contexa.autoconfigure.iam.IamMiscAutoConfiguration,io.contexa.autoconfigure.iam.IamResourceAutoConfiguration,io.contexa.autoconfigure.iam.IamSecurityAutoConfiguration,io.contexa.autoconfigure.iam.IamSecurityCoreAutoConfiguration,io.contexa.autoconfigure.iam.IamWebSocketAutoConfiguration,io.contexa.autoconfigure.iam.xacml.IamXacmlPapAutoConfiguration,io.contexa.autoconfigure.iam.xacml.IamXacmlPdpAutoConfiguration,io.contexa.autoconfigure.iam.xacml.IamXacmlPepAutoConfiguration,io.contexa.autoconfigure.iam.xacml.IamXacmlPipAutoConfiguration,io.contexa.autoconfigure.iam.xacml.IamXacmlPrpAutoConfiguration,io.contexa.autoconfigure.identity.IdentityAsepAutoConfiguration,io.contexa.autoconfigure.identity.IdentityHandlerAutoConfiguration,io.contexa.autoconfigure.identity.IdentityMfaAutoConfiguration,io.contexa.autoconfigure.identity.IdentityOAuth2AutoConfiguration,io.contexa.autoconfigure.identity.IdentitySecurityCoreAutoConfiguration,io.contexa.autoconfigure.identity.IdentityServiceAutoConfiguration,io.contexa.autoconfigure.identity.IdentityStateMachineAutoConfiguration,io.contexa.autoconfigure.identity.IdentityWebAuthnAutoConfiguration,io.contexa.contexacore.config.CoreSecurityAutoConfiguration,org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration",
                "contexa.enterprise.enabled=true",
                "contexa.enterprise.benchmark.publication.report-root=D:/contexa-enterprise/spring-boot-starter-contexa-enterprise/build/reports/official-verification-fullstack-benchmark"
        })
class PublicBenchmarkDatabaseBootstrapTest {

    private static final String SLUG = "official-verification-fullstack-benchmark";

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PublishedBenchmarkReleaseStore publishedBenchmarkReleaseStore;

    @Autowired
    private BenchmarkPublicationProperties properties;

    @Test
    void startupBackfillsPublishedReleaseIntoDatabaseAndPublicOverviewReadsIt() throws Exception {
        assertThat(publishedBenchmarkReleaseStore.findPublishedArtifact(SLUG)).isNotNull();
        String benchmarkName = objectMapper.readTree(Files.readString(Path.of(properties.getReportRoot()).resolve("summary.json")))
                .path("benchmarkName")
                .asText();

        ResponseEntity<String> overview = restTemplate.getForEntity(url("/benchmark"), String.class);

        assertThat(overview.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(overview.getBody()).contains(benchmarkName);
        assertThat(overview.getBody()).contains("/benchmark/reports/" + SLUG);
        assertThat(overview.getBody()).doesNotContain("No published report.");
    }

    @Test
    void startupBackfillMakesPublishedSummaryAvailableWithoutRegeneratingFromRequest() throws Exception {
        ResponseEntity<String> response = restTemplate.getForEntity(url("/benchmark/reports/" + SLUG + "/summary.json"), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode summary = objectMapper.readTree(response.getBody());
        assertThat(summary.path("slug").asText()).isEqualTo(SLUG);
        assertThat(summary.path("status").asText()).isEqualTo("PUBLISHED");
        assertThat(summary.path("officialMetricCount").asInt()).isEqualTo(14);
        assertThat(summary.path("provenance").path("sourceVerifiedCaseCount").asInt()).isGreaterThan(0);
    }

    @SpringBootApplication(scanBasePackages = "io.contexa.site")
    @ComponentScan(basePackages = "io.contexa.site", excludeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = ContexaSiteApplication.class))
    @EntityScan(basePackageClasses = {PublishedBenchmarkReleaseRecord.class, BenchmarkRunLedgerRecord.class, VerificationRunLedgerRecord.class})
    @Import(BenchmarkPublicationCoreConfiguration.class)
    static class TestSiteApplication {
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class TestBenchmarkBootstrapConfiguration {

        @Bean
        OfficialVerificationMetricCatalog officialVerificationMetricCatalog() {
            return new OfficialVerificationMetricCatalog();
        }
    }

    private String url(String path) {
        return "http://127.0.0.1:" + port + path;
    }
}