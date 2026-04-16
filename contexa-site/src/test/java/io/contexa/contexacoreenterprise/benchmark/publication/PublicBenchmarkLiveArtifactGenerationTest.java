package io.contexa.contexacoreenterprise.benchmark.publication;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacoreenterprise.benchmark.EvaluationMaterializationService;
import io.contexa.contexacoreenterprise.benchmark.UnifiedTruthAuditTrailService;
import io.contexa.contexacoreenterprise.benchmark.VerificationBenchmarkTruthCoreService;
import io.contexa.contexacoreenterprise.benchmark.report.OpenTrustBenchmarkReportDatasetBuilder;
import io.contexa.site.controller.PublicBenchmarkController;
import io.contexa.site.service.PublicBenchmarkFacade;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileSystemUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(
        classes = PublicBenchmarkLiveArtifactGenerationTest.TestApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.messages.basename=i18n/messages-site,i18n/messages-enterprise,i18n/messages",
                "spring.thymeleaf.cache=false",
                "spring.autoconfigure.exclude=io.contexa.autoconfigure.core.advisor.CoreAdvisorAutoConfiguration,io.contexa.autoconfigure.core.autonomous.CoreAutonomousAutoConfiguration,io.contexa.autoconfigure.core.autonomous.CoreAutonomousEventAutoConfiguration,io.contexa.autoconfigure.core.autonomous.CoreAutonomousStrategyAutoConfiguration,io.contexa.autoconfigure.core.autonomous.CoreSaasForwardingAutoConfiguration,io.contexa.autoconfigure.core.CoreDataAutoConfiguration,io.contexa.autoconfigure.core.hcad.CoreHCADAutoConfiguration,io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration,io.contexa.autoconfigure.core.infra.CoreInfrastructureExtendedAutoConfiguration,io.contexa.autoconfigure.core.llm.CoreLLMAutoConfiguration,io.contexa.autoconfigure.core.llm.CoreLLMTieredAutoConfiguration,io.contexa.autoconfigure.core.rag.CoreRAGAutoConfiguration,io.contexa.autoconfigure.core.session.CoreSessionAutoConfiguration,io.contexa.autoconfigure.core.std.CoreStdComponentsAutoConfiguration,io.contexa.autoconfigure.core.streaming.CoreStreamingAutoConfiguration,io.contexa.autoconfigure.enterprise.dashboard.EnterpriseDashboardAutoConfiguration,io.contexa.autoconfigure.enterprise.EnterpriseJpaAutoConfiguration,io.contexa.autoconfigure.enterprise.iam.IamEnterpriseAutoConfiguration,io.contexa.autoconfigure.enterprise.iam.IamEnterpriseI18nAutoConfiguration,io.contexa.autoconfigure.enterprise.soar.EnterpriseAiNativeOperationsAutoConfiguration,io.contexa.autoconfigure.enterprise.soar.EnterpriseSoarAutoConfiguration,io.contexa.autoconfigure.enterprise.tool.EnterpriseToolAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminAccessCenterAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminAuthAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminBlacklistAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminCenterAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminIpAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminMetadataAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminMonitoringAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminPasswordPolicyAutoConfiguration,io.contexa.autoconfigure.iam.admin.IamAdminSessionAutoConfiguration,io.contexa.autoconfigure.iam.aiam.IamAiamComponentsAutoConfiguration,io.contexa.autoconfigure.iam.aiam.IamAiamInfrastructureAutoConfiguration,io.contexa.autoconfigure.iam.aiam.IamAiamLabsAutoConfiguration,io.contexa.autoconfigure.iam.aiam.IamAiamServiceStrategyAutoConfiguration,io.contexa.autoconfigure.iam.aiam.IamAiamWebAutoConfiguration,io.contexa.autoconfigure.iam.aiam.IamAiamZeroTrustSseAutoConfiguration,io.contexa.autoconfigure.iam.IamI18nAutoConfiguration,io.contexa.autoconfigure.iam.IamInfrastructureAutoConfiguration,io.contexa.autoconfigure.iam.IamMiscAutoConfiguration,io.contexa.autoconfigure.iam.IamResourceAutoConfiguration,io.contexa.autoconfigure.iam.IamSecurityAutoConfiguration,io.contexa.autoconfigure.iam.IamSecurityCoreAutoConfiguration,io.contexa.autoconfigure.iam.IamWebSocketAutoConfiguration,io.contexa.autoconfigure.iam.xacml.IamXacmlPapAutoConfiguration,io.contexa.autoconfigure.iam.xacml.IamXacmlPdpAutoConfiguration,io.contexa.autoconfigure.iam.xacml.IamXacmlPepAutoConfiguration,io.contexa.autoconfigure.iam.xacml.IamXacmlPipAutoConfiguration,io.contexa.autoconfigure.iam.xacml.IamXacmlPrpAutoConfiguration,io.contexa.autoconfigure.identity.IdentityAsepAutoConfiguration,io.contexa.autoconfigure.identity.IdentityHandlerAutoConfiguration,io.contexa.autoconfigure.identity.IdentityMfaAutoConfiguration,io.contexa.autoconfigure.identity.IdentityOAuth2AutoConfiguration,io.contexa.autoconfigure.identity.IdentitySecurityCoreAutoConfiguration,io.contexa.autoconfigure.identity.IdentityServiceAutoConfiguration,io.contexa.autoconfigure.identity.IdentityStateMachineAutoConfiguration,io.contexa.autoconfigure.identity.IdentityWebAuthnAutoConfiguration,io.contexa.contexacore.config.CoreSecurityAutoConfiguration,org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration,org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration",
                "contexa.enterprise.benchmark.publication.report-root=D:/contexa-enterprise/spring-boot-starter-contexa-enterprise/build/reports/official-verification-fullstack-benchmark"
        })
class PublicBenchmarkLiveArtifactGenerationTest {

    private static final String SLUG = "official-verification-fullstack-benchmark";
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private BenchmarkPublicationProperties properties;

    @Autowired
    private OpenTrustBenchmarkPublicationService publicationService;

    @BeforeEach
    void resetPublishedArtifacts() throws IOException {
        FileSystemUtils.deleteRecursively(publicArtifactDirectory());
    }

    @Test
    void summaryEndpointGeneratesPublishedArtifactsFromRealBenchmarkRoot() throws Exception {
        Map<String, Object> rawSummary = readRawSummary();
        Map<String, Object> rawCoverage = map(rawSummary.get("officialMetricCoverage"));

        ResponseEntity<String> response = restTemplate.getForEntity(url("/benchmark/reports/" + SLUG + "/summary.json"), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode summary = objectMapper.readTree(response.getBody());
        Path publicDir = publicArtifactDirectory();
        assertThat(Files.isDirectory(publicDir)).isTrue();
        assertThat(Files.exists(publicDir.resolve("summary.json"))).isTrue();
        assertThat(Files.exists(publicDir.resolve("chart-data.json"))).isTrue();
        assertThat(Files.exists(publicDir.resolve("manifest.json"))).isTrue();
        assertThat(Files.exists(publicDir.resolve("report.html"))).isTrue();
        assertThat(Files.exists(publicDir.resolve("report.pdf"))).isTrue();

        assertThat(summary.path("slug").asText()).isEqualTo(SLUG);
        assertThat(summary.path("benchmarkVersion").asText()).isEqualTo(String.valueOf(rawSummary.get("benchmarkVersion")));
        assertThat(summary.path("runCount").asInt()).isEqualTo(((Number) rawSummary.get("runCount")).intValue());
        assertThat(summary.path("officialMetricCount").asInt()).isEqualTo(((Number) rawCoverage.get("officialMetricCount")).intValue());
        assertThat(summary.path("observedOfficialMetricCount").asInt()).isEqualTo(((Number) rawCoverage.get("observedOfficialMetricCount")).intValue());
        assertThat(summary.path("overallCoveragePercent").asDouble()).isEqualTo(((Number) rawCoverage.get("observedOfficialCoveragePercent")).doubleValue());
        assertThat(toSet(summary.path("missingOfficialMetrics"))).isEqualTo(new LinkedHashSet<>(strings(rawCoverage.get("missingOfficialMetricNames"))));
        assertThat(toSet(summary.path("scenarioFamilies"))).isEqualTo(new LinkedHashSet<>(strings(rawSummary.get("observedScenarioFamilies"))));
        assertThat(toSet(summary.path("officialMetrics"), "code")).isEqualTo(new LinkedHashSet<>(strings(rawCoverage.get("observedOfficialMetricCodes"))));
        assertThat(summary.path("provenance").path("sourceVerifiedCaseCount").asInt()).isGreaterThan(0);
        assertThat(summary.path("provenance").path("sourceEvaluationCaseCount").asInt()).isGreaterThan(0);
        assertThat(summary.path("claims").isArray()).isTrue();
        assertThat(summary.path("claims").size()).isGreaterThan(0);
    }

    @Test
    void httpEndpointsExposeRealBenchmarkDossierDataAfterArtifactGeneration() throws Exception {
        ResponseEntity<String> summaryResponse = restTemplate.getForEntity(url("/benchmark/reports/" + SLUG + "/summary.json"), String.class);
        assertThat(summaryResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<String, Object> rawSummary = readRawSummary();

        ResponseEntity<String> overview = restTemplate.getForEntity(url("/benchmark"), String.class);
        assertThat(overview.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(overview.getBody()).contains("Published report catalog");
        assertThat(overview.getBody()).contains(String.valueOf(rawSummary.get("benchmarkName")));
        assertThat(overview.getBody()).contains("78.57%");

        ResponseEntity<String> report = restTemplate.getForEntity(url("/benchmark/reports/" + SLUG), String.class);
        assertThat(report.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(report.getBody()).contains("Truth provenance");
        assertThat(report.getBody()).contains("Claim scorecard");
        assertThat(report.getBody()).contains("Official metric safety gate");
        assertThat(report.getBody()).contains("Evaluation suite breakdown");
        assertThat(report.getBody()).contains("Scenario matrix");
        assertThat(report.getBody()).contains("Trend and version comparison");
        assertThat(report.getBody()).contains("Source artifacts");
        assertThat(report.getBody()).doesNotContain("This page is a navigation lens");

        ResponseEntity<String> chartData = restTemplate.getForEntity(url("/benchmark/reports/" + SLUG + "/chart-data.json"), String.class);
        assertThat(chartData.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode chart = objectMapper.readTree(chartData.getBody());
        assertThat(chart.path("officialGate").path("officialMetricCount").asInt()).isEqualTo(14);
        assertThat(chart.path("scenarioMatrix").isArray()).isTrue();
        assertThat(chart.path("scenarioMatrix").size()).isGreaterThan(0);
        assertThat(chart.path("trend").isArray()).isTrue();
        assertThat(chart.path("claimScoreBand").isArray()).isTrue();
        assertThat(chart.path("claimScoreBand").size()).isGreaterThan(0);

        ResponseEntity<String> exportedHtml = restTemplate.getForEntity(url("/benchmark/reports/" + SLUG + "/html"), String.class);
        assertThat(exportedHtml.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(exportedHtml.getHeaders().getContentType()).isNotNull();
        assertThat(exportedHtml.getHeaders().getContentType().isCompatibleWith(MediaType.TEXT_HTML)).isTrue();
        assertThat(exportedHtml.getBody()).contains("Truth Provenance");
        assertThat(exportedHtml.getBody()).contains("Official Metric Safety Gate");
        assertThat(exportedHtml.getBody()).contains("Scenario Matrix");
        assertThat(exportedHtml.getBody()).contains("Trend and Version Comparison");

        ResponseEntity<byte[]> exportedPdf = restTemplate.getForEntity(url("/benchmark/reports/" + SLUG + "/pdf"), byte[].class);
        assertThat(exportedPdf.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(exportedPdf.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PDF);
        assertThat(exportedPdf.getBody()).isNotNull();
        assertThat(exportedPdf.getBody().length).isGreaterThan(1024);
    }

    private Map<String, Object> readRawSummary() throws IOException {
        return objectMapper.readValue(Files.readString(Path.of(properties.getReportRoot()).resolve("summary.json")), MAP_TYPE);
    }

    private Path publicArtifactDirectory() {
        return Path.of(properties.getReportRoot())
                .resolve(properties.getPublicationDirectoryName())
                .resolve("public")
                .resolve(SLUG);
    }

    private String url(String path) {
        return "http://127.0.0.1:" + port + path;
    }

    private Map<String, Object> map(Object value) {
        if (value instanceof Map<?, ?> raw) {
            return raw.entrySet().stream().collect(java.util.stream.Collectors.toMap(
                    entry -> String.valueOf(entry.getKey()),
                    Map.Entry::getValue,
                    (left, right) -> right,
                    java.util.LinkedHashMap::new));
        }
        return Map.of();
    }

    private List<String> strings(Object value) {
        if (value instanceof List<?> raw) {
            return raw.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    private Set<String> toSet(JsonNode arrayNode) {
        Set<String> values = new LinkedHashSet<>();
        if (arrayNode != null && arrayNode.isArray()) {
            arrayNode.forEach(node -> values.add(node.asText()));
        }
        return values;
    }

    private Set<String> toSet(JsonNode arrayNode, String fieldName) {
        Set<String> values = new LinkedHashSet<>();
        if (arrayNode != null && arrayNode.isArray()) {
            arrayNode.forEach(node -> values.add(node.path(fieldName).asText()));
        }
        return values;
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration(exclude = {
            DataSourceAutoConfiguration.class,
            HibernateJpaAutoConfiguration.class,
            RedisAutoConfiguration.class,
            RedisRepositoriesAutoConfiguration.class,
            SecurityAutoConfiguration.class,
            ManagementWebSecurityAutoConfiguration.class
    })
    @Import({PublicBenchmarkController.class, PublicBenchmarkFacade.class})
    static class TestApplication {
        @Bean
        BenchmarkPublicationProperties benchmarkPublicationProperties() {
            BenchmarkPublicationProperties properties = new BenchmarkPublicationProperties();
            properties.setReportRoot("D:/contexa-enterprise/spring-boot-starter-contexa-enterprise/build/reports/official-verification-fullstack-benchmark");
            return properties;
        }

        @Bean
        BenchmarkPublicationRegistryStore benchmarkPublicationRegistryStore(ObjectMapper objectMapper,
                                                                            BenchmarkPublicationProperties properties) {
            return new BenchmarkPublicationRegistryStore(objectMapper, properties);
        }

        @Bean
        BenchmarkPublicReportAssembler benchmarkPublicReportAssembler(ObjectMapper objectMapper) {
            return new BenchmarkPublicReportAssembler(objectMapper);
        }

        @Bean
        OpenTrustBenchmarkPrivateReportAssembler openTrustBenchmarkPrivateReportAssembler() {
            return new OpenTrustBenchmarkPrivateReportAssembler();
        }

        @Bean
        UnifiedTruthAuditTrailService unifiedTruthAuditTrailService(BenchmarkPublicationProperties properties,
                                                                    ObjectMapper objectMapper) {
            return new UnifiedTruthAuditTrailService(properties, objectMapper);
        }

        @Bean
        EvaluationMaterializationService evaluationMaterializationService(UnifiedTruthAuditTrailService auditTrailService) {
            return new EvaluationMaterializationService(new VerificationBenchmarkTruthCoreService(), auditTrailService);
        }

        @Bean
        OpenTrustBenchmarkPublicationSanitizer openTrustBenchmarkPublicationSanitizer(EvaluationMaterializationService evaluationMaterializationService) {
            return new OpenTrustBenchmarkPublicationSanitizer(evaluationMaterializationService);
        }

        @Bean
        OpenTrustBenchmarkChartDatasetBuilder openTrustBenchmarkChartDatasetBuilder(BenchmarkPublicReportAssembler benchmarkPublicReportAssembler) {
            return new OpenTrustBenchmarkChartDatasetBuilder(benchmarkPublicReportAssembler, new OpenTrustBenchmarkReportDatasetBuilder());
        }

        @Bean
        OpenTrustBenchmarkPublicReportAssembler openTrustBenchmarkPublicReportAssembler() {
            return new OpenTrustBenchmarkPublicReportAssembler();
        }

        @Bean
        OpenTrustBenchmarkHtmlReportBuilder openTrustBenchmarkHtmlReportBuilder() {
            return new OpenTrustBenchmarkHtmlReportBuilder();
        }

        @Bean
        OpenTrustBenchmarkPdfReportBuilder openTrustBenchmarkPdfReportBuilder() {
            return new OpenTrustBenchmarkPdfReportBuilder();
        }

        @Bean
        BenchmarkPublicationService benchmarkPublicationService(BenchmarkPublicationProperties properties,
                                                                ObjectMapper objectMapper,
                                                                BenchmarkPublicationRegistryStore registryStore,
                                                                BenchmarkPublicReportAssembler assembler,
                                                                OpenTrustBenchmarkPrivateReportAssembler privateReportAssembler,
                                                                OpenTrustBenchmarkPublicationSanitizer publicationSanitizer,
                                                                OpenTrustBenchmarkChartDatasetBuilder chartDatasetBuilder,
                                                                OpenTrustBenchmarkPublicReportAssembler publicReportAssembler,
                                                                OpenTrustBenchmarkHtmlReportBuilder htmlReportBuilder,
                                                                OpenTrustBenchmarkPdfReportBuilder pdfReportBuilder,
                                                                UnifiedTruthAuditTrailService auditTrailService) {
            return new BenchmarkPublicationService(
                    properties,
                    objectMapper,
                    registryStore,
                    assembler,
                    privateReportAssembler,
                    publicationSanitizer,
                    chartDatasetBuilder,
                    publicReportAssembler,
                    htmlReportBuilder,
                    pdfReportBuilder,
                    auditTrailService);
        }

        @Bean
        OpenTrustBenchmarkPublicationService openTrustBenchmarkPublicationService(BenchmarkPublicationService benchmarkPublicationService) {
            return new OpenTrustBenchmarkPublicationService(benchmarkPublicationService);
        }
    }
}