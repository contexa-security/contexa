package io.contexa.site.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacoreenterprise.benchmark.contract.BenchmarkClaimResult;
import io.contexa.contexacoreenterprise.benchmark.contract.BenchmarkFacetResult;
import io.contexa.contexacoreenterprise.benchmark.contract.BenchmarkProvenanceSummary;
import io.contexa.contexacoreenterprise.benchmark.contract.PublishedBenchmarkMetricView;
import io.contexa.contexacoreenterprise.benchmark.contract.PublishedBenchmarkScenarioMatrix;
import io.contexa.contexacoreenterprise.benchmark.contract.PublishedBenchmarkSuiteView;
import io.contexa.contexacoreenterprise.benchmark.contract.PublishedBenchmarkTrendView;
import io.contexa.contexacoreenterprise.benchmark.publication.BenchmarkPublicationStatus;
import io.contexa.contexacoreenterprise.benchmark.publication.BenchmarkPublicArtifact;
import io.contexa.contexacoreenterprise.benchmark.publication.BenchmarkPublicSiteProjection;
import io.contexa.contexacoreenterprise.benchmark.publication.PublishedBenchmarkManifest;
import io.contexa.contexacoreenterprise.benchmark.publication.PublishedBenchmarkSummary;
import io.contexa.contexacoreenterprise.benchmark.publication.BenchmarkPublicationView;
import io.contexa.contexacoreenterprise.benchmark.publication.OpenTrustBenchmarkPublicationService;
import io.contexa.contexacoreenterprise.benchmark.publication.PartnerCertificationProfileView;
import io.contexa.site.service.PublicBenchmarkFacade;
import io.contexa.site.service.PublicBenchmarkSiteView;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.context.MessageSource;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Locale;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@ExtendWith(MockitoExtension.class)
class PublicBenchmarkControllerTest {

    @Mock
    private PublicBenchmarkFacade facade;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setPrefix("/templates/");
        viewResolver.setSuffix(".html");
        mockMvc = MockMvcBuilders.standaloneSetup(new PublicBenchmarkController(facade))
                .setMessageConverters(new MappingJackson2HttpMessageConverter(new ObjectMapper().registerModule(new JavaTimeModule())))
                .setViewResolvers(viewResolver)
                .build();
    }

    @Test
    void overviewRendersBenchmarkPage() throws Exception {
        when(facade.overview(any())).thenReturn("site/benchmark-overview");

        mockMvc.perform(get("/benchmark"))
                .andExpect(status().isOk())
                .andExpect(view().name("site/benchmark-overview"));
    }

    @Test
    void directFamilyRouteRendersFamilyPage() throws Exception {
        when(facade.family(eq("human"), any())).thenReturn("site/benchmark-family");

        mockMvc.perform(get("/benchmark/human"))
                .andExpect(status().isOk())
                .andExpect(view().name("site/benchmark-family"));
    }

    @Test
    void methodologyRendersPage() throws Exception {
        when(facade.methodology(any())).thenReturn("site/benchmark-methodology");

        mockMvc.perform(get("/benchmark/methodology"))
                .andExpect(status().isOk())
                .andExpect(view().name("site/benchmark-methodology"));
    }

    @Test
    void detailRendersReportPage() throws Exception {
        when(facade.detail(eq("official"), any())).thenReturn("site/benchmark-report");

        mockMvc.perform(get("/benchmark/reports/official"))
                .andExpect(status().isOk())
                .andExpect(view().name("site/benchmark-report"));
    }

    @Test
    void summaryJsonRendersPublishedSummary() throws Exception {
        when(facade.summary("official")).thenReturn(sampleSummary());

        mockMvc.perform(get("/benchmark/reports/official/summary.json"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.slug").value("official"))
                .andExpect(jsonPath("$.scenarioFamilies[0]").value("human"))
                .andExpect(jsonPath("$.suiteSummaries[0].key").value("implementation-alignment"))
                .andExpect(jsonPath("$.scenarioMatrix.rows[0].delta").value(2.5d))
                .andExpect(jsonPath("$.scenarioMatrix.rows[0].claimKeys[0]").value("HUMAN_POST_AUTH_ZERO_TRUST"))
                .andExpect(jsonPath("$.scenarioMatrix.rows[0].suiteKeys[0]").value("IMPLEMENTATION_ALIGNMENT"))
                .andExpect(jsonPath("$.trendView.points[0].versionMarker").value("v1"))
                .andExpect(jsonPath("$.trendView.points[0].sourceLabel").value("OFFICIAL_BENCHMARK"))
                .andExpect(jsonPath("$.trendView.points[0].deltaFromPrevious").value(1.5d))
                .andExpect(jsonPath("$.provenance.sourceVerifiedCaseCount").value(14))
                .andExpect(jsonPath("$.claims[0].key").value("HUMAN_POST_AUTH_ZERO_TRUST"));
    }

    @Test
    void manifestJsonRendersPublishedManifest() throws Exception {
        when(facade.manifest("official")).thenReturn(new PublishedBenchmarkManifest(
                "official",
                "Official Benchmark",
                "v1",
                "OFFICIAL_BENCHMARK",
                BenchmarkPublicationStatus.PUBLISHED,
                Instant.parse("2026-04-11T00:00:00Z"),
                Instant.parse("2026-04-11T01:00:00Z"),
                "system",
                List.of("summary.json", "report.html"),
                "VBUTC-METHOD-2026.04.11-v1",
                "VBUTC-SANITIZE-2026.04.11-v1",
                "VBUTC-SUITE-2026.04.11-v1",
                14,
                14,
                14,
                "official@v1|VBUTC-METHOD-2026.04.11-v1",
                Map.of("summary.json", "abc123", "report.pdf", "def456")));

        mockMvc.perform(get("/benchmark/reports/official/manifest.json"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.slug").value("official"))
                .andExpect(jsonPath("$.publishedFiles[0]").value("summary.json"))
                .andExpect(jsonPath("$.methodologyVersion").value("VBUTC-METHOD-2026.04.11-v1"))
                .andExpect(jsonPath("$.manifestIdentity").value("official@v1|VBUTC-METHOD-2026.04.11-v1"))
                .andExpect(jsonPath("$.artifactSha256['summary.json']").value("abc123"));
    }

    @Test
    void chartDataJsonRendersPublishedChartDataset() throws Exception {
        Map<String, Object> chartData = new LinkedHashMap<>();
        chartData.put("coveragePercent", 97.5d);
        chartData.put("groupedBarChart", List.of(Map.of("label", "Human coverage")));
        chartData.put("claimScoreBand", List.of(Map.of("claimKey", "HUMAN_POST_AUTH_ZERO_TRUST", "score", 97.5d)));
        chartData.put("publicationTimeline", List.of(Map.of("label", "Run 1", "versionMarker", "v1")));
        chartData.put("officialGate", Map.of("officialMetricCount", 3, "missingOfficialMetricCount", 0));
        when(facade.chartData("official")).thenReturn(chartData);

        mockMvc.perform(get("/benchmark/reports/official/chart-data.json"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.coveragePercent").value(97.5d))
                .andExpect(jsonPath("$.groupedBarChart[0].label").value("Human coverage"))
                .andExpect(jsonPath("$.claimScoreBand[0].claimKey").value("HUMAN_POST_AUTH_ZERO_TRUST"))
                .andExpect(jsonPath("$.publicationTimeline[0].versionMarker").value("v1"))
                .andExpect(jsonPath("$.officialGate.officialMetricCount").value(3));
    }

    @Test
    void detailReturnsNotFoundWhenSlugIsUnknown() throws Exception {
        when(facade.detail(eq("missing"), any()))
                .thenThrow(new IllegalArgumentException("missing"));

        mockMvc.perform(get("/benchmark/missing"))
                .andExpect(status().isNotFound());
    }

    @Test
    void overviewBuildsCatalogServerModelWhenPublishedDataExists() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();
        PublishedBenchmarkSummary summary = sampleSummary();
        PartnerCertificationProfileView profile = new PartnerCertificationProfileView(
                "spring-profile",
                "Spring Application Profile",
                "Spring runtime evidence mapping.",
                List.of("human", "verification", "java-fit"),
                true,
                1,
                List.of("official"),
                "official",
                List.of("HUMAN_POST_AUTH_ZERO_TRUST"),
                List.of("implementation-alignment"),
                "Published public evidence satisfies the required signal set.",
                "1 dossier mapped.",
                "Publication-safe only.");
        when(publicationService.getPublishedSummaries()).thenReturn(List.of(summary));
        when(publicationService.getCustomerSubmissionSummaries()).thenReturn(List.of());
        when(publicationService.getPartnerCertificationProfiles()).thenReturn(List.of(profile));
        when(publicationService.getPublishedCatalogSnapshot()).thenReturn(new BenchmarkPublicationView.CatalogSnapshot(
                Instant.parse("2026-04-11T01:00:00Z"),
                "D:/reports",
                true,
                1,
                1,
                List.of()));

        String viewName = realFacade.overview(model);

        assertEquals("site/benchmark-overview", viewName);
        PublicBenchmarkSiteView.CatalogHero hero = (PublicBenchmarkSiteView.CatalogHero) model.getAttribute("catalogHero");
        assertNotNull(hero);
        assertEquals("official", hero.slug());
        assertEquals("/benchmark/reports/official", hero.dossierUrl());
        List<?> statusRail = (List<?>) model.getAttribute("catalogStatusRail");
        assertEquals(4, statusRail.size());
        List<?> reportRows = (List<?>) model.getAttribute("catalogReportRows");
        assertEquals(1, reportRows.size());
        PublicBenchmarkSiteView.CatalogFilterMetadata filters = (PublicBenchmarkSiteView.CatalogFilterMetadata) model.getAttribute("catalogFilterMetadata");
        assertFalse(filters.families().isEmpty());
        assertTrue(filters.sortOptions().stream().anyMatch(option -> option.value().equals("latest")));
        List<?> certificationRows = (List<?>) model.getAttribute("catalogCertificationSnapshotRows");
        assertEquals(1, certificationRows.size());
        assertEquals(Boolean.TRUE, model.getAttribute("catalogHasPublishedReports"));
    }

    @Test
    void overviewUsesStoredPublicProjectionWhenAvailable() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();
        PublishedBenchmarkSummary summary = sampleSummary();
        BenchmarkPublicSiteProjection.OverviewProjection projection = new BenchmarkPublicSiteProjection.OverviewProjection(
                Instant.parse("2026-04-11T02:00:00Z"),
                1,
                0,
                "official",
                List.of(new BenchmarkPublicSiteProjection.FamilyAggregate("verification", "verification", 1, 1)),
                List.of("verification"),
                List.of("PUBLISHED"),
                List.of("OFFICIAL_BENCHMARK"),
                List.of(new BenchmarkPublicSiteProjection.ReportAggregate(
                        "official",
                        "Official Benchmark",
                        "OVFB-2026.04",
                        "OFFICIAL_BENCHMARK",
                        List.of("verification"),
                        97.5d,
                        3,
                        3,
                        1,
                        1,
                        1,
                        14,
                        14,
                        0,
                        true,
                        BenchmarkPublicationStatus.PUBLISHED,
                        Instant.parse("2026-04-11T01:00:00Z"))),
                List.of(new BenchmarkPublicSiteProjection.ClaimLandscapeAggregate(
                        "HUMAN_POST_AUTH_ZERO_TRUST",
                        "Human Post-Auth Zero Trust",
                        1,
                        1,
                        97.5d,
                        List.of("verification"))),
                List.of(new BenchmarkPublicSiteProjection.TrendAggregate(
                        "official",
                        "FIRST_PARTY",
                        "Official Benchmark",
                        "OVFB-2026.04",
                        Instant.parse("2026-04-11T00:00:00Z"),
                        97.5d,
                        3,
                        3,
                        BenchmarkPublicationStatus.PUBLISHED)),
                List.of(new BenchmarkPublicSiteProjection.LeaderboardAggregate(
                        1,
                        "FIRST_PARTY",
                        "official",
                        "Official Benchmark",
                        "OVFB-2026.04",
                        97.5d,
                        3,
                        3,
                        true,
                        BenchmarkPublicationStatus.PUBLISHED)),
                List.of(new BenchmarkPublicSiteProjection.CertificationSnapshotAggregate(
                        "spring-profile",
                        "Spring Application Profile",
                        true,
                        1,
                        "official",
                        "Published evidence exists.",
                        List.of("verification"))));
        when(publicationService.getPublicOverviewProjection()).thenReturn(projection);
        when(publicationService.getPublishedCatalogSnapshot()).thenReturn(new BenchmarkPublicationView.CatalogSnapshot(
                Instant.parse("2026-04-11T01:00:00Z"),
                "db://published_benchmark_release",
                true,
                1,
                1,
                List.of()));
        when(publicationService.getPublishedArtifact("official")).thenReturn(new BenchmarkPublicArtifact(
                summary,
                Map.of("coveragePercent", 97.5d),
                sampleManifest(),
                "<html>report</html>",
                new byte[]{1, 2, 3}));

        String viewName = realFacade.overview(model);

        assertEquals("site/benchmark-overview", viewName);
        assertEquals(Boolean.TRUE, model.getAttribute("catalogHasPublishedReports"));
        assertEquals(1, ((List<?>) model.getAttribute("catalogReportRows")).size());
        assertEquals(1, ((List<?>) model.getAttribute("catalogCertificationSnapshotRows")).size());
        verify(publicationService, never()).getPublishedSummaries();
        verify(publicationService, never()).getCustomerSubmissionSummaries();
    }

    @Test
    void overviewBuildsSlimStatusRailWhenNoPublicationExists() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();
        when(publicationService.getPublishedSummaries()).thenReturn(List.of());
        when(publicationService.getCustomerSubmissionSummaries()).thenReturn(List.of());
        when(publicationService.getPartnerCertificationProfiles()).thenReturn(List.of());
        when(publicationService.getPublishedCatalogSnapshot()).thenReturn(new BenchmarkPublicationView.CatalogSnapshot(
                Instant.parse("2026-04-11T01:00:00Z"),
                "D:/reports",
                true,
                0,
                0,
                List.of()));

        String viewName = realFacade.overview(model);

        assertEquals("site/benchmark-overview", viewName);
        assertNull(model.getAttribute("catalogHero"));
        @SuppressWarnings("unchecked")
        List<PublicBenchmarkSiteView.CatalogStatusItem> statusRail = (List<PublicBenchmarkSiteView.CatalogStatusItem>) model.getAttribute("catalogStatusRail");
        assertEquals(4, statusRail.size());
        assertEquals("No published report", statusRail.get(0).value());
        assertEquals(Boolean.FALSE, model.getAttribute("catalogHasPublishedReports"));
    }

    @Test
    void detailBuildsDossierServerModel() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();
        BenchmarkPublicArtifact artifact = new BenchmarkPublicArtifact(
                sampleSummary(),
                Map.of("officialGate", Map.of("officialMetricCount", 3)),
                sampleManifest(),
                "<html>report</html>",
                new byte[]{1, 2, 3});
        when(publicationService.getPublishedArtifact("official")).thenReturn(artifact);

        String viewName = realFacade.detail("official", model);

        assertEquals("site/benchmark-report", viewName);
        assertNotNull(model.getAttribute("dossierHero"));
        assertNotNull(model.getAttribute("dossierExecutiveSummary"));
        assertFalse(((List<?>) model.getAttribute("dossierClaimScorecardRows")).isEmpty());
        assertNotNull(model.getAttribute("dossierTruthProvenance"));
        assertNotNull(model.getAttribute("dossierOfficialGate"));
        assertNotNull(model.getAttribute("dossierExploitWindow"));
        assertFalse(((List<?>) model.getAttribute("dossierSuiteBreakdownRows")).isEmpty());
        assertFalse(((List<?>) model.getAttribute("dossierScenarioMatrixRows")).isEmpty());
        assertFalse(((List<?>) model.getAttribute("dossierTrendComparisonRows")).isEmpty());
        assertFalse(((List<?>) model.getAttribute("dossierMethodologyConstraints")).isEmpty());
        assertFalse(((List<?>) model.getAttribute("dossierSourceArtifacts")).isEmpty());
    }
    @Test
    void familyBuildsLensServerModelWhenPublishedDataExists() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();
        PublishedBenchmarkSummary summary = sampleSummary();
        when(publicationService.getPublishedSummaries()).thenReturn(List.of(summary));

        String viewName = realFacade.family("human", model);

        assertEquals("site/benchmark-family", viewName);
        PublicBenchmarkSiteView.FamilyCard card = (PublicBenchmarkSiteView.FamilyCard) model.getAttribute("familyCard");
        assertNotNull(card);
        assertEquals("human", card.slug());
        @SuppressWarnings("unchecked")
        List<PublicBenchmarkSiteView.CatalogStatusItem> lensStatusRail = (List<PublicBenchmarkSiteView.CatalogStatusItem>) model.getAttribute("lensStatusRail");
        assertEquals(4, lensStatusRail.size());
        assertEquals("1", lensStatusRail.get(0).value());
        assertNotNull(model.getAttribute("lensLatestDossier"));
        assertEquals(1, ((List<?>) model.getAttribute("lensReportRows")).size());
        PublicBenchmarkSiteView.TrendChartView chart = (PublicBenchmarkSiteView.TrendChartView) model.getAttribute("lensTrendMiniChart");
        assertFalse(chart.points().isEmpty());
        assertEquals(Boolean.TRUE, model.getAttribute("lensHasPublishedReports"));
    }

    @Test
    void familyBuildsSlimStatusRailWhenNoPublicationExists() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();
        when(publicationService.getPublishedSummaries()).thenReturn(List.of());

        String viewName = realFacade.family("verification", model);

        assertEquals("site/benchmark-family", viewName);
        assertNull(model.getAttribute("lensLatestDossier"));
        @SuppressWarnings("unchecked")
        List<PublicBenchmarkSiteView.CatalogStatusItem> lensStatusRail = (List<PublicBenchmarkSiteView.CatalogStatusItem>) model.getAttribute("lensStatusRail");
        assertEquals(4, lensStatusRail.size());
        assertEquals("No published report", lensStatusRail.get(0).value());
        assertEquals(Boolean.FALSE, model.getAttribute("lensHasPublishedReports"));
    }
    @Test
    void methodologyBuildsAppendixServerModel() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();

        String viewName = realFacade.methodology(model);

        assertEquals("site/benchmark-methodology", viewName);
        assertFalse(((List<?>) model.getAttribute("methodologyInterpretationRules")).isEmpty());
        assertFalse(((List<?>) model.getAttribute("methodologyStandardAlignmentRows")).isEmpty());
        assertFalse(((List<?>) model.getAttribute("methodologyPublicBoundaryRules")).isEmpty());
    }

    @Test
    void trendsBuildsSeparatedAppendixServerModel() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();
        when(publicationService.getPublishedSummaries()).thenReturn(List.of(sampleSummary()));
        when(publicationService.getCustomerSubmissionSummaries()).thenReturn(List.of());

        String viewName = realFacade.trends(model);

        assertEquals("site/benchmark-trends", viewName);
        assertFalse(((List<?>) model.getAttribute("publishedTrendRows")).isEmpty());
        assertNotNull(model.getAttribute("trendSourceBoundary"));
        assertNotNull(model.getAttribute("trendComparisonRows"));
    }

    @Test
    void certificationBuildsEvidenceAppendixModel() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();
        PartnerCertificationProfileView profile = new PartnerCertificationProfileView(
                "spring-profile",
                "Spring Application Profile",
                "Spring runtime evidence mapping.",
                List.of("human", "verification", "java-fit"),
                true,
                1,
                List.of("official"),
                "official",
                List.of("HUMAN_POST_AUTH_ZERO_TRUST"),
                List.of("implementation-alignment"),
                "Published public evidence satisfies the required signal set.",
                "1 dossier mapped.",
                "Publication-safe only.");
        when(publicationService.getPartnerCertificationProfiles()).thenReturn(List.of(profile));
        when(publicationService.getPublishedSummaries()).thenReturn(List.of(sampleSummary()));
        when(publicationService.getCustomerSubmissionSummaries()).thenReturn(List.of());

        String viewName = realFacade.certification(model);

        assertEquals("site/benchmark-certification", viewName);
        assertEquals(1, ((List<?>) model.getAttribute("certificationProfileMatrix")).size());
        assertEquals(1, ((List<?>) model.getAttribute("certificationEvidenceRows")).size());
        assertNotNull(model.getAttribute("certificationBoundaryNote"));
    }

    @Test
    void selfRunBuildsPublicationAcceptanceRules() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();
        when(publicationService.getCustomerSubmissionSummaries()).thenReturn(List.of());

        String viewName = realFacade.selfRun(model);

        assertEquals("site/benchmark-self-run", viewName);
        assertFalse(((List<?>) model.getAttribute("publicationBundleAcceptanceRules")).isEmpty());
    }
    @Test
    void benchmarkTemplatesExposeCatalogLensAndAppendixStructure() throws Exception {
        String overview = Files.readString(Path.of("src", "main", "resources", "templates", "site", "benchmark-overview.html"));
        String family = Files.readString(Path.of("src", "main", "resources", "templates", "site", "benchmark-family.html"));
        String certification = Files.readString(Path.of("src", "main", "resources", "templates", "site", "benchmark-certification.html"));

        assertTrue(overview.contains("site.benchmark.overview.current.kicker"));
        assertTrue(overview.contains("site.benchmark.overview.claims.title"));
        assertTrue(overview.contains("site.benchmark.overview.certification.title"));
        assertTrue(family.contains("site.benchmark.family.summary.title"));
        assertTrue(family.contains("site.benchmark.family.compare.title"));
        assertTrue(certification.contains("site.benchmark.certification.ui.matrix-title"));
        assertTrue(certification.contains("site.benchmark.certification.ui.detail-title"));
        assertFalse(family.contains("This page is a navigation lens"));
        assertFalse(certification.contains("How certification profiles work"));
    }

    @Test
    void reportTemplateExposesCanonicalDossierSections() throws Exception {
        String report = Files.readString(Path.of("src", "main", "resources", "templates", "site", "benchmark-report.html"));

        assertTrue(report.contains("Report verdict"));
        assertTrue(report.contains("Evidence chain"));
        assertTrue(report.contains("Claim verdicts"));
        assertTrue(report.contains("Official metrics"));
        assertTrue(report.contains("Response proof"));
        assertTrue(report.contains("Which test groups produced the result"));
        assertTrue(report.contains("Scenario results"));
        assertTrue(report.contains("Version change"));
        assertTrue(report.contains("Reading rules"));
        assertTrue(report.contains("Source artifacts"));
        assertTrue(report.contains("Claims"));
        assertTrue(report.contains("Suites"));
        assertTrue(report.contains("row.deviationClass"));
        assertTrue(report.contains("Version"));
        assertTrue(report.contains("Source"));
        assertTrue(report.contains("Delta"));
    }

    @Test
    void renderedDossierTemplateIncludesCanonicalDataWithoutTemplateResidue() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();
        BenchmarkPublicArtifact artifact = new BenchmarkPublicArtifact(
                sampleSummary(),
                Map.of("officialGate", Map.of("officialMetricCount", 3)),
                sampleManifest(),
                "<html>report</html>",
                new byte[]{1, 2, 3});
        when(publicationService.getPublishedArtifact("official")).thenReturn(artifact);

        realFacade.detail("official", model);
        String rendered = renderTemplate("site/benchmark-report", model);

        assertTrue(rendered.contains("Human Post-Auth Zero Trust"));
        assertTrue(rendered.contains("Human Post-Auth Zero Trust"));
        assertTrue(rendered.contains("above-threshold"));
        assertTrue(rendered.contains("OFFICIAL_BENCHMARK"));
        assertTrue(rendered.contains("1.50%"));
        assertFalse(rendered.contains("th:text"));
        assertFalse(rendered.contains("th:each"));
    }

    @Test
    void renderedFamilyTemplateKeepsLensAsDataSurfaceInsteadOfEssay() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();
        when(publicationService.getPublishedSummaries()).thenReturn(List.of(sampleSummary()));

        realFacade.family("human", model);
        String rendered = renderTemplate("site/benchmark-family", model);

        assertTrue(rendered.contains("How to use this topic view"));
        assertTrue(rendered.contains("Compare related topics side by side"));
        assertTrue(rendered.contains("How to use this topic view"));
        assertTrue(rendered.contains("Browse every related public report"));
        assertFalse(rendered.contains("This page is a navigation lens"));
        assertFalse(rendered.contains("Every lens should converge on a single authoritative report"));
        assertFalse(rendered.contains("Methodology links"));
    }

    @Test
    void renderedOverviewTemplateResolvesMessagesWithoutCodeLeak() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();
        PublishedBenchmarkSummary summary = sampleSummary();
        PartnerCertificationProfileView profile = new PartnerCertificationProfileView(
                "spring-profile",
                "Spring Application Profile",
                "Spring runtime evidence mapping.",
                List.of("human", "verification", "java-fit"),
                true,
                1,
                List.of("official"),
                "official",
                List.of("HUMAN_POST_AUTH_ZERO_TRUST"),
                List.of("implementation-alignment"),
                "Published public evidence satisfies the required signal set.",
                "1 dossier mapped.",
                "Publication-safe only.");
        when(publicationService.getPublishedSummaries()).thenReturn(List.of(summary));
        when(publicationService.getCustomerSubmissionSummaries()).thenReturn(List.of());
        when(publicationService.getPartnerCertificationProfiles()).thenReturn(List.of(profile));
        when(publicationService.getPublishedCatalogSnapshot()).thenReturn(new BenchmarkPublicationView.CatalogSnapshot(
                Instant.parse("2026-04-11T01:00:00Z"),
                "D:/reports",
                true,
                1,
                1,
                List.of()));

        realFacade.overview(model);
        String rendered = renderTemplate("site/benchmark-overview", model);

        assertTrue(rendered.contains("Read it in this order"));
        assertTrue(rendered.contains("Open the official report first."));
        assertTrue(rendered.contains("Official Benchmark"));
        assertFalse(rendered.contains("site.benchmark.overview.reading.title"));
        assertFalse(rendered.contains("site.benchmark.overview.reading.step1"));
        assertFalse(rendered.contains("site.benchmark.overview.reading.step2"));
        assertFalse(rendered.contains("site.benchmark.overview.reading.step3"));
    }

    @Test
    void renderedTrendsTemplateUsesTrendRowsWithoutFieldMismatch() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();
        PublishedBenchmarkSummary published = sampleSummary();
        PublishedBenchmarkSummary customer = new PublishedBenchmarkSummary(
                "customer-official",
                "Customer Benchmark",
                "v1",
                "CUSTOMER_SELF_RUN",
                BenchmarkPublicationStatus.PUBLISHED,
                Instant.parse("2026-04-12T00:00:00Z"),
                Instant.parse("2026-04-12T00:10:00Z"),
                "system",
                Instant.parse("2026-04-12T00:20:00Z"),
                1,
                82.0d,
                3,
                3,
                3,
                0,
                true,
                List.of("human"),
                List.of(),
                List.of("summary.json"),
                List.of(new PublishedBenchmarkMetricView("HZT-1", "Customer coverage", "human", 82.0d, 80.0d, true, "STABLE", true, true)),
                List.of(new PublishedBenchmarkSuiteView("implementation-alignment", "Implementation Alignment Suite", 11, 11, 82.0d, true)),
                new PublishedBenchmarkScenarioMatrix(List.of(new PublishedBenchmarkScenarioMatrix.Row(
                        "HZT-1",
                        "Customer coverage",
                        "human",
                        82.0d,
                        80.0d,
                        true,
                        2.0d,
                        List.of("HUMAN_POST_AUTH_ZERO_TRUST"),
                        List.of("IMPLEMENTATION_ALIGNMENT"),
                        "above-threshold"))),
                new PublishedBenchmarkTrendView(List.of(new PublishedBenchmarkTrendView.Point(
                        "Run 2",
                        Instant.parse("2026-04-12T00:00:00Z"),
                        "v1",
                        "customer",
                        "CUSTOMER_SELF_RUN",
                        82.0d,
                        3,
                        0,
                        0.5d))),
                null,
                new BenchmarkProvenanceSummary(11, 11, 11, 1.0d, 1.0d, "VBUTC-TRUTH-2026.04.12-v1", "VBUTC-EVAL-2026.04.12-v1", "VBUTC-METHOD-2026.04.12-v1", "VBUTC-SANITIZE-2026.04.12-v1", "VBUTC-SUITE-2026.04.12-v1", Instant.parse("2026-04-12T00:00:00Z")),
                List.of(new BenchmarkClaimResult("HUMAN_POST_AUTH_ZERO_TRUST", "Human Post-Auth Zero Trust", List.of("IMPLEMENTATION_ALIGNMENT"), List.of("HZT-1"), 82.0d, 11, 11, true, List.of())),
                List.of(new BenchmarkFacetResult("human", "Human", 1, 11, 82.0d, true)));
        when(publicationService.getPublishedSummaries()).thenReturn(List.of(published));
        when(publicationService.getCustomerSubmissionSummaries()).thenReturn(List.of(customer));

        realFacade.trends(model);
        String rendered = renderTemplate("site/benchmark-trends", model);

        assertTrue(rendered.contains("Official Benchmark"));
        assertTrue(rendered.contains("Customer Benchmark"));

        assertFalse(rendered.contains("generatedLabel"));
    }

    @Test
    void renderedCertificationTemplateUsesProfileFieldsWithoutMismatch() {
        OpenTrustBenchmarkPublicationService publicationService = mock(OpenTrustBenchmarkPublicationService.class);
        MessageSource messageSource = benchmarkMessageSource();
        PublicBenchmarkFacade realFacade = new PublicBenchmarkFacade(publicationService, messageSource);
        ExtendedModelMap model = new ExtendedModelMap();
        PartnerCertificationProfileView profile = new PartnerCertificationProfileView(
                "spring-profile",
                "Spring Application Profile",
                "Spring runtime evidence mapping.",
                List.of("human", "verification", "java-fit"),
                true,
                1,
                List.of("official"),
                "official",
                List.of("HUMAN_POST_AUTH_ZERO_TRUST"),
                List.of("implementation-alignment"),
                "Published public evidence satisfies the required signal set.",
                "1 dossier mapped.",
                "Publication-safe only.");
        when(publicationService.getPartnerCertificationProfiles()).thenReturn(List.of(profile));
        when(publicationService.getPublishedSummaries()).thenReturn(List.of(sampleSummary()));
        when(publicationService.getCustomerSubmissionSummaries()).thenReturn(List.of());

        realFacade.certification(model);
        String rendered = renderTemplate("site/benchmark-certification", model);

        assertTrue(rendered.contains("Spring Application Profile"));
        assertTrue(rendered.contains("Published public evidence satisfies the required signal set."));
        assertTrue(rendered.contains("Publication-safe only."));
    }
    private String renderTemplate(String templateName, ExtendedModelMap model) {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        resolver.setCacheable(false);

        ReloadableResourceBundleMessageSource messageSource = new ReloadableResourceBundleMessageSource();
        messageSource.setBasename("classpath:i18n/messages-site");
        messageSource.setDefaultEncoding("UTF-8");
        messageSource.setFallbackToSystemLocale(false);
        messageSource.setUseCodeAsDefaultMessage(true);

        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolver(resolver);
        engine.setTemplateEngineMessageSource(messageSource);

        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext);
        request.setContextPath("");
        request.setRequestURI("/benchmark/test");
        MockHttpServletResponse response = new MockHttpServletResponse();
        WebContext context = new WebContext(
                JakartaServletWebApplication.buildApplication(servletContext).buildExchange(request, response),
                Locale.ENGLISH,
                model);
        return engine.process(templateName, context);
    }

    private MessageSource benchmarkMessageSource() {
        MessageSource messageSource = mock(MessageSource.class);
        lenient().when(messageSource.getMessage(anyString(), nullable(Object[].class), nullable(String.class), any(java.util.Locale.class)))
                .thenAnswer(invocation -> {
                    String defaultMessage = invocation.getArgument(2);
                    return defaultMessage != null ? defaultMessage : invocation.getArgument(0);
                });
        lenient().when(messageSource.getMessage(anyString(), nullable(Object[].class), any(java.util.Locale.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        return messageSource;
    }
    private PublishedBenchmarkManifest sampleManifest() {
        return new PublishedBenchmarkManifest(
                "official",
                "Official Benchmark",
                "v1",
                "OFFICIAL_BENCHMARK",
                BenchmarkPublicationStatus.PUBLISHED,
                Instant.parse("2026-04-11T00:00:00Z"),
                Instant.parse("2026-04-11T01:00:00Z"),
                "system",
                List.of("summary.json", "chart-data.json", "manifest.json", "report.html", "report.pdf"),
                "VBUTC-METHOD-2026.04.11-v1",
                "VBUTC-SANITIZE-2026.04.11-v1",
                "VBUTC-SUITE-2026.04.11-v1",
                14,
                14,
                14,
                "official@v1|VBUTC-METHOD-2026.04.11-v1",
                Map.of("summary.json", "abc123", "report.pdf", "def456"));
    }
    private PublishedBenchmarkSummary sampleSummary() {
        return new PublishedBenchmarkSummary(
                "official",
                "Official Benchmark",
                "v1",
                "OFFICIAL_BENCHMARK",
                BenchmarkPublicationStatus.PUBLISHED,
                Instant.parse("2026-04-11T00:00:00Z"),
                Instant.parse("2026-04-11T00:10:00Z"),
                "system",
                Instant.parse("2026-04-11T00:20:00Z"),
                1,
                97.5d,
                3,
                3,
                3,
                0,
                true,
                List.of("human"),
                List.of(),
                List.of("summary.json"),
                List.of(new PublishedBenchmarkMetricView("HZT-1", "Human coverage", "human", 97.5d, 95.0d, true, "STABLE", true, true)),
                List.of(new PublishedBenchmarkSuiteView("implementation-alignment", "Implementation Alignment Suite", 14, 14, 97.5d, true)),
                new PublishedBenchmarkScenarioMatrix(List.of(new PublishedBenchmarkScenarioMatrix.Row(
                        "HZT-1",
                        "Human coverage",
                        "human",
                        97.5d,
                        95.0d,
                        true,
                        2.5d,
                        List.of("HUMAN_POST_AUTH_ZERO_TRUST"),
                        List.of("IMPLEMENTATION_ALIGNMENT"),
                        "above-threshold"))),
                new PublishedBenchmarkTrendView(List.of(new PublishedBenchmarkTrendView.Point(
                        "Run 1",
                        Instant.parse("2026-04-11T00:00:00Z"),
                        "v1",
                        "latest",
                        "OFFICIAL_BENCHMARK",
                        97.5d,
                        3,
                        0,
                        1.5d))),
                null,
                new BenchmarkProvenanceSummary(14, 14, 14, 1.0d, 1.0d, "VBUTC-TRUTH-2026.04.11-v1", "VBUTC-EVAL-2026.04.11-v1", "VBUTC-METHOD-2026.04.11-v1", "VBUTC-SANITIZE-2026.04.11-v1", "VBUTC-SUITE-2026.04.11-v1", Instant.parse("2026-04-11T00:00:00Z")),
                List.of(new BenchmarkClaimResult("HUMAN_POST_AUTH_ZERO_TRUST", "Human Post-Auth Zero Trust", List.of("IMPLEMENTATION_ALIGNMENT"), List.of("HZT-1"), 97.5d, 14, 14, true, List.of())),
                List.of(new BenchmarkFacetResult("human", "Human", 1, 14, 97.5d, true)));
    }
}
