package io.contexa.site.service;

import io.contexa.contexacoreenterprise.benchmark.contract.BenchmarkClaimResult;
import io.contexa.contexacoreenterprise.benchmark.contract.BenchmarkFacetResult;
import io.contexa.contexacoreenterprise.benchmark.contract.PublishedBenchmarkScenarioMatrix;
import io.contexa.contexacoreenterprise.benchmark.contract.PublishedBenchmarkTrendView;
import io.contexa.contexacoreenterprise.benchmark.exploit.ExploitWindowControlResult;
import io.contexa.contexacoreenterprise.benchmark.publication.BenchmarkPublicationView;
import io.contexa.contexacoreenterprise.benchmark.publication.BenchmarkPublicSiteProjection;
import io.contexa.contexacoreenterprise.benchmark.publication.OpenTrustBenchmarkPublicationService;
import io.contexa.contexacoreenterprise.benchmark.publication.PartnerCertificationProfileView;
import io.contexa.contexacoreenterprise.benchmark.publication.PublishedBenchmarkManifest;
import io.contexa.contexacoreenterprise.benchmark.publication.PublishedBenchmarkSummary;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Service
public class PublicBenchmarkFacade {

    private static final double TREND_CHART_WIDTH = 560.0d;
    private static final double TREND_CHART_HEIGHT = 220.0d;
    private static final double TREND_CHART_PADDING_X = 40.0d;
    private static final double TREND_CHART_PADDING_Y = 24.0d;
    private static final DateTimeFormatter DATE_LABEL = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DATE_TIME_LABEL = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    private final OpenTrustBenchmarkPublicationService publicationService;
    private final MessageSource messageSource;

    public PublicBenchmarkFacade(OpenTrustBenchmarkPublicationService publicationService, MessageSource messageSource) {
        this.publicationService = publicationService;
        this.messageSource = messageSource;
    }

    public String overview(Model model) {
        BenchmarkPublicSiteProjection.OverviewProjection projection = publicationService.getPublicOverviewProjection();
        if (projection != null) {
            return overviewFromProjection(model, projection);
        }
        List<PublishedBenchmarkSummary> published = publicationService.getPublishedSummaries().stream()
                .sorted(Comparator.comparing(PublishedBenchmarkSummary::generatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .toList();
        List<PublishedBenchmarkSummary> customerSubmissions = publicationService.getCustomerSubmissionSummaries();
        BenchmarkPublicationView.CatalogSnapshot catalog = publicationService.getPublishedCatalogSnapshot();
        PublishedBenchmarkSummary featuredReport = published.stream().findFirst().orElse(null);
        List<PartnerCertificationProfileView> certificationProfiles = publicationService.getPartnerCertificationProfiles();
        var methodologySections = methodologySections();
        var featuredFamilies = featuredFamilies(published);
        var facetRoutes = facetRoutes(published, null);
        var leaderboardRows = buildLeaderboardRows(published, customerSubmissions);
        var claimLandscapeRows = buildClaimLandscape(published);
        var overviewTrendRows = buildTrendRows(msg("site.benchmark.common.first-party"), published);
        var catalogReportRows = buildCatalogReportRows(published);
        var certificationSnapshotRows = buildCertificationSnapshotRows(certificationProfiles);
        var featuredReportDonut = featuredReport != null ? buildDonut(featuredReport) : emptyDonut();
        var featuredReportTrendChart = featuredReport != null ? buildTrendChart(featuredReport) : emptyTrendChart();
        var featuredScenarioRows = featuredReport != null ? buildScenarioRows(featuredReport).stream().limit(4).toList() : List.of();
        var catalogHero = buildCatalogHero(featuredReport);
        model.addAttribute("pageTitle", msg("site.benchmark.facade.overview-title"));
        model.addAttribute("catalog", catalog);
        model.addAttribute("methodologySections", methodologySections);
        model.addAttribute("featuredFamilies", featuredFamilies);
        model.addAttribute("facetRoutes", facetRoutes);
        model.addAttribute("certificationProfiles", certificationProfiles);
        model.addAttribute("customerSubmissionCount", customerSubmissions.size());
        model.addAttribute("leaderboardRows", leaderboardRows.stream().limit(5).toList());
        model.addAttribute("overviewCards", overviewSummaryCards(catalog, customerSubmissions.size(), featuredReport));
        model.addAttribute("featuredReport", spotlight(featuredReport));
        model.addAttribute("publishedReportSpotlights", published.stream().limit(3).map(this::spotlight).toList());
        model.addAttribute("claimLandscapeRows", claimLandscapeRows);
        model.addAttribute("overviewTrendRows", overviewTrendRows.stream().limit(6).toList());
        model.addAttribute("featuredReportDonut", featuredReportDonut);
        model.addAttribute("featuredReportTrendChart", featuredReportTrendChart);
        model.addAttribute("featuredScenarioRows", featuredScenarioRows);
        model.addAttribute("catalogHero", catalogHero);
        model.addAttribute("catalogStatusRail", buildCatalogStatusRail(catalog, customerSubmissions.size(), certificationProfiles, featuredReport));
        model.addAttribute("catalogReportRows", catalogReportRows);
        model.addAttribute("catalogFilterMetadata", buildCatalogFilterMetadata(published));
        model.addAttribute("catalogTrendSnapshotRows", overviewTrendRows.stream().limit(8).toList());
        model.addAttribute("catalogCertificationSnapshotRows", certificationSnapshotRows);
        model.addAttribute("catalogHasPublishedReports", !published.isEmpty());
        return "site/benchmark-overview";
    }
    public String detail(String slug, Model model) {
        var artifact = publicationService.getPublishedArtifact(slug);
        PublishedBenchmarkSummary report = artifact.summary();
        PublishedBenchmarkManifest manifest = artifact.manifest();
        var reportExecutive = buildReportExecutive(report);
        var claimScoreRows = buildReportClaimScoreRows(report);
        var scenarioRows = buildScenarioRows(report);
        var trendComparisonRows = buildTrendComparisonRows(report);
        var artifactCards = buildReportArtifactCards(slug, manifest);
        var reportConstraints = buildReportConstraints(report, manifest);
        var officialMetrics = safeOfficialMetrics(report);
        var suiteRows = safeSuites(report);
        var reportDonut = buildDonut(report);
        var reportTrendChart = buildTrendChart(report);
        var heatmapCells = buildHeatmapCells(report);
        model.addAttribute("pageTitle", msg("site.benchmark.facade.report-title"));
        model.addAttribute("report", report);
        model.addAttribute("reportManifest", manifest);
        model.addAttribute("reportExecutive", reportExecutive);
        model.addAttribute("reportClaimHighlights", buildClaimHighlights(report));
        model.addAttribute("reportClaimScoreRows", claimScoreRows);
        model.addAttribute("reportExploitSummaryCards", buildExploitSummaryCards(report));
        model.addAttribute("reportGateSummaryCards", buildReportGateSummaryCards(report));
        model.addAttribute("reportOfficialMetrics", officialMetrics);
        model.addAttribute("reportHtmlUrl", "/benchmark/reports/" + slug + "/html");
        model.addAttribute("reportPdfUrl", "/benchmark/reports/" + slug + "/pdf");
        model.addAttribute("reportSummaryUrl", "/benchmark/reports/" + slug + "/summary.json");
        model.addAttribute("reportChartDataUrl", "/benchmark/reports/" + slug + "/chart-data.json");
        model.addAttribute("reportManifestUrl", "/benchmark/reports/" + slug + "/manifest.json");
        model.addAttribute("reportDonut", reportDonut);
        model.addAttribute("reportTrendChart", reportTrendChart);
        model.addAttribute("reportHeatmapCells", heatmapCells);
        model.addAttribute("reportFailingMetrics", officialMetrics.stream().filter(metric -> !metric.pass()).toList());
        model.addAttribute("reportScenarioRows", scenarioRows);
        model.addAttribute("reportTrendComparisonRows", trendComparisonRows);
        model.addAttribute("reportExploitCases", safeExploitCases(report));
        model.addAttribute("reportExploitClaims", safeExploitClaims(report));
        model.addAttribute("reportArtifactCards", artifactCards);
        model.addAttribute("reportConstraints", reportConstraints);
        model.addAttribute("reportReadyFacetCount", (int) safeFacets(report).stream().filter(BenchmarkFacetResult::publicationReady).count());

        model.addAttribute("dossierHero", buildDossierHero(report));
        model.addAttribute("dossierExecutiveSummary", reportExecutive);
        model.addAttribute("dossierClaimScorecardRows", claimScoreRows);
        model.addAttribute("dossierTruthProvenance", buildDossierProvenance(report, manifest));
        model.addAttribute("dossierOfficialGate", buildDossierOfficialGate(report));
        model.addAttribute("dossierExploitWindow", buildDossierExploitWindow(report));
        model.addAttribute("dossierSuiteBreakdownRows", suiteRows);
        model.addAttribute("dossierScenarioMatrixRows", scenarioRows);
        model.addAttribute("dossierTrendComparisonRows", trendComparisonRows);
        model.addAttribute("dossierMethodologyConstraints", reportConstraints);
        model.addAttribute("dossierSourceArtifacts", artifactCards);
        return "site/benchmark-report";
    }
    public String methodology(Model model) {
        model.addAttribute("pageTitle", msg("site.benchmark.facade.methodology-title"));
        model.addAttribute("methodologySections", methodologySections());
        model.addAttribute("methodologyInterpretationRules", methodologyInterpretationRules());
        model.addAttribute("methodologyStandardAlignmentRows", methodologyStandardAlignmentRows());
        model.addAttribute("methodologyPublicBoundaryRules", methodologyPublicBoundaryRules());
        return "site/benchmark-methodology";
    }
    public String trends(Model model) {
        BenchmarkPublicSiteProjection.TrendsProjection projection = publicationService.getPublicTrendsProjection();
        if (projection != null) {
            return trendsFromProjection(model, projection);
        }
        List<PublishedBenchmarkSummary> published = publicationService.getPublishedSummaries();
        List<PublishedBenchmarkSummary> customerSubmissions = publicationService.getCustomerSubmissionSummaries();
        var publishedTrendRows = buildTrendRows(msg("site.benchmark.common.first-party"), published);
        var customerTrendRows = buildTrendRows(msg("site.benchmark.common.customer-selfrun"), customerSubmissions);
        var trendComparisonRows = new ArrayList<PublicBenchmarkSiteView.TrendRow>();
        trendComparisonRows.addAll(publishedTrendRows);
        trendComparisonRows.addAll(customerTrendRows);
        model.addAttribute("pageTitle", msg("site.benchmark.facade.trends-title"));
        model.addAttribute("publishedTrendRows", publishedTrendRows);
        model.addAttribute("customerTrendRows", customerTrendRows);
        model.addAttribute("leaderboardRows", buildLeaderboardRows(published, customerSubmissions));
        model.addAttribute("trendComparisonRows", trendComparisonRows);
        model.addAttribute("trendSourceBoundary", "First-party published dossiers and customer self-run bundles remain separated on the public appendix surface.");
        return "site/benchmark-trends";
    }
    public String family(String family, Model model) {
        String routeSlug = routeSlugForFamily(family);
        BenchmarkPublicSiteProjection.FamilyProjection projection = publicationService.getPublicFamilyProjection(routeSlug);
        if (projection != null) {
            return familyFromProjection(routeSlug, model, projection);
        }
        List<PublishedBenchmarkSummary> published = publicationService.getPublishedSummaries();
        String normalized = normalizeFamily(family);
        List<PublicBenchmarkSiteView.FacetRouteCard> relatedRoutes = facetRoutes(published, normalized);
        PublicBenchmarkSiteView.FamilyCard card = featuredFamilies(published).stream()
                .filter(item -> item.slug().equals(normalized))
                .findFirst()
                .orElse(new PublicBenchmarkSiteView.FamilyCard(normalized, familyTitle(normalized), familySummary(normalized), 0, 0));
        List<PublishedBenchmarkSummary> reports = published.stream()
                .filter(summary -> matchesFamily(summary, normalized))
                .sorted(Comparator.comparing(PublishedBenchmarkSummary::generatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .toList();
        PublishedBenchmarkSummary latestReport = reports.stream().findFirst().orElse(null);
        var familyClaimLandscape = buildClaimLandscape(reports);
        var familyTrendRows = buildTrendRows(msg("site.benchmark.common.first-party"), reports);
        var latestSpotlight = spotlight(latestReport);
        var latestReportDonut = latestReport != null ? buildDonut(latestReport) : emptyDonut();
        var latestReportTrendChart = latestReport != null ? buildTrendChart(latestReport) : emptyTrendChart();
        var latestScenarioRows = latestReport != null ? buildScenarioRows(latestReport).stream().limit(4).toList() : List.of();
        model.addAttribute("pageTitle", card.title());
        model.addAttribute("familyCard", card);
        model.addAttribute("reports", reports);
        model.addAttribute("familySummaryCards", familySummaryCards(card, reports, latestReport));
        model.addAttribute("facetRoutes", relatedRoutes);
        model.addAttribute("latestReport", latestSpotlight);
        model.addAttribute("latestReportDonut", latestReportDonut);
        model.addAttribute("latestReportTrendChart", latestReportTrendChart);
        model.addAttribute("latestScenarioRows", latestScenarioRows);
        model.addAttribute("familyClaimLandscape", familyClaimLandscape);
        model.addAttribute("familyTrendRows", familyTrendRows.stream().limit(6).toList());
        model.addAttribute("methodologySections", methodologySections());
        model.addAttribute("familyReadyRatio", reports.isEmpty() ? 0.0d : (((double) reports.stream().filter(PublishedBenchmarkSummary::submissionReady).count()) * 100.0d / reports.size()));

        model.addAttribute("lensStatusRail", buildLensStatusRail(card, reports, latestReport));
        model.addAttribute("lensLatestDossier", latestSpotlight);
        model.addAttribute("lensClaimDistribution", familyClaimLandscape);
        model.addAttribute("lensTrendMiniChart", buildTrendChart(reports));
        model.addAttribute("lensReportRows", buildCatalogReportRows(reports));
        model.addAttribute("relatedLensRoutes", relatedRoutes);
        model.addAttribute("lensHasPublishedReports", !reports.isEmpty());
        return "site/benchmark-family";
    }
    public String leaderboard(Model model) {
        BenchmarkPublicSiteProjection.LeaderboardProjection projection = publicationService.getPublicLeaderboardProjection();
        if (projection != null) {
            return leaderboardFromProjection(model, projection);
        }
        model.addAttribute("pageTitle", msg("site.benchmark.facade.leaderboard-title"));
        model.addAttribute("leaderboardRows", buildLeaderboardRows(publicationService.getPublishedSummaries(), publicationService.getCustomerSubmissionSummaries()));
        model.addAttribute("leaderboardSortOptions", List.of(
                new PublicBenchmarkSiteView.CatalogOption("coverage", "Coverage"),
                new PublicBenchmarkSiteView.CatalogOption("ready", "Submission readiness"),
                new PublicBenchmarkSiteView.CatalogOption("source", "Source separation")));
        model.addAttribute("leaderboardSourceBoundary", "Published first-party dossiers and customer self-run bundles remain source-separated in the public comparison surface.");
        return "site/benchmark-leaderboard";
    }
    public String selfRun(Model model) {
        model.addAttribute("pageTitle", msg("site.benchmark.facade.selfrun-title"));
        model.addAttribute("customerSubmissions", publicationService.getCustomerSubmissionSummaries());
        model.addAttribute("intakeRequirements", List.of(
                msg("site.benchmark.selfrun.req1"),
                msg("site.benchmark.selfrun.req2"),
                msg("site.benchmark.selfrun.req3"),
                msg("site.benchmark.selfrun.req4")));
        model.addAttribute("publicationBundleAcceptanceRules", publicationBundleAcceptanceRules());
        return "site/benchmark-self-run";
    }
    public String certification(Model model) {
        List<PartnerCertificationProfileView> profiles = publicationService.getPartnerCertificationProfiles();
        model.addAttribute("pageTitle", msg("site.benchmark.facade.certification-title"));
        model.addAttribute("profiles", profiles);
        model.addAttribute("publishedCount", publicationService.getPublishedSummaries().size());
        model.addAttribute("customerSubmissionCount", publicationService.getCustomerSubmissionSummaries().size());
        model.addAttribute("certificationProfileMatrix", buildCertificationProfileMatrix(profiles));
        model.addAttribute("certificationEvidenceRows", buildCertificationEvidenceRows(profiles));
        model.addAttribute("certificationBoundaryNote", "Certification appendix maps only publication-safe benchmark dossiers and publication-safe customer bundles. It does not invent a partner-issued score.");
        return "site/benchmark-certification";
    }
    public PublishedBenchmarkSummary summary(String slug) {
        return publicationService.getPublishedArtifact(slug).summary();
    }

    public Map<String, Object> chartData(String slug) {
        return publicationService.getPublishedArtifact(slug).chartDataset();
    }

    public PublishedBenchmarkManifest manifest(String slug) {
        return publicationService.getPublishedArtifact(slug).manifest();
    }

    public String reportHtml(String slug) {
        return publicationService.getPublishedHtmlReport(slug);
    }

    public byte[] reportPdf(String slug) {
        return publicationService.getPublishedPdfReport(slug);
    }

    private String msg(String key) {
        return messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
    }

    private List<String> methodologyInterpretationRules() {
        return List.of(
                "Missing official metrics are held as missing, not rendered as zero.",
                "Published scores must be read together with methodology, sanitization, and suite versions.",
                "Submission-ready state requires official safety gates and publication-safe evidence integrity.");
    }

    private List<PublicBenchmarkSiteView.MethodologyAlignmentRow> methodologyStandardAlignmentRows() {
        return List.of(
                new PublicBenchmarkSiteView.MethodologyAlignmentRow("nist-airmf", "NIST AI RMF", "Benchmark interpretation stays anchored to traceability, measurement integrity, and public risk communication.", "Public dossiers should explain how measured controls map to risk-management expectations."),
                new PublicBenchmarkSiteView.MethodologyAlignmentRow("owasp-agentic", "OWASP Agentic Applications", "Scenario families and exploit-window proof should map runtime control evidence to agentic risk classes.", "Published benchmark evidence should speak the same risk language external reviewers already use."),
                new PublicBenchmarkSiteView.MethodologyAlignmentRow("openid-authzen", "OpenID AuthZEN / protocol boundary", "Protocol-boundary claims should remain tied to interoperable authorization semantics and permit continuity.", "Public reports need to show where runtime enforcement aligns with boundary and delegation semantics."));
    }

    private List<String> methodologyPublicBoundaryRules() {
        return List.of(
                "Only publication-approved artifacts are exposed on the public site.",
                "Raw tenant traces, internal request payloads, and enterprise-only evidence stay outside the public dossier.",
                "HTML, PDF, summary, chart-data, and manifest stay bound to the same sanitized publication envelope.");
    }

    private List<String> publicationBundleAcceptanceRules() {
        return List.of(
                "Submission bundles must satisfy the same publication-safe boundary as first-party published dossiers.",
                "Verification-derived truth, methodology version, and suite version must be attached before public intake succeeds.",
                "Customer bundles are listed publicly only after publication-safe review and artifact generation complete.");
    }

    private List<PublicBenchmarkSiteView.CertificationProfileMatrixRow> buildCertificationProfileMatrix(List<PartnerCertificationProfileView> profiles) {
        return profiles.stream()
                .map(profile -> new PublicBenchmarkSiteView.CertificationProfileMatrixRow(
                        profile.key(),
                        profile.title(),
                        profile.ready(),
                        profile.matchingReportCount(),
                        profile.latestMappedReport(),
                        profile.ready() ? "success" : "warning",
                        profile.requiredSignals()))
                .toList();
    }

    private List<PublicBenchmarkSiteView.CertificationEvidenceRow> buildCertificationEvidenceRows(List<PartnerCertificationProfileView> profiles) {
        return profiles.stream()
                .map(profile -> new PublicBenchmarkSiteView.CertificationEvidenceRow(
                        profile.key(),
                        profile.title(),
                        profile.requiredSignals(),
                        profile.matchingSlugs(),
                        profile.mappedClaimKeys(),
                        profile.mappedSuiteKeys(),
                        profile.readinessBasis(),
                        profile.evidenceStatusDetails(),
                        profile.profileNote()))
                .toList();
    }
    private String overviewFromProjection(Model model, BenchmarkPublicSiteProjection.OverviewProjection projection) {
        BenchmarkPublicationView.CatalogSnapshot catalog = publicationService.getPublishedCatalogSnapshot();
        BenchmarkPublicSiteProjection.ReportAggregate featuredAggregate = findReportAggregate(projection.reportRows(), projection.featuredReportSlug());
        PublishedBenchmarkSummary featuredReport = featuredAggregate != null ? loadPublishedSummary(featuredAggregate.slug()) : null;
        List<PublicBenchmarkSiteView.CertificationSnapshotRow> certificationSnapshotRows = toCertificationSnapshotRows(projection.certificationSnapshotRows());
        List<PublicBenchmarkSiteView.TrendRow> overviewTrendRows = toTrendRows(projection.publishedTrendRows());
        model.addAttribute("pageTitle", msg("site.benchmark.facade.overview-title"));
        model.addAttribute("catalog", catalog);
        model.addAttribute("methodologySections", methodologySections());
        model.addAttribute("featuredFamilies", featuredFamilies(projection));
        model.addAttribute("facetRoutes", facetRoutesFromProjection(projection.families(), null));
        model.addAttribute("customerSubmissionCount", projection.customerSubmissionCount());
        model.addAttribute("leaderboardRows", toLeaderboardRows(projection.leaderboardRows()).stream().limit(5).toList());
        model.addAttribute("overviewCards", overviewSummaryCards(catalog, projection.customerSubmissionCount(), featuredReport));
        model.addAttribute("featuredReport", featuredAggregate != null ? spotlight(featuredAggregate) : null);
        model.addAttribute("publishedReportSpotlights", projection.reportRows().stream().limit(3).map(this::spotlight).toList());
        model.addAttribute("claimLandscapeRows", toClaimLandscapeRows(projection.claimLandscapeRows()));
        model.addAttribute("overviewTrendRows", overviewTrendRows.stream().limit(6).toList());
        model.addAttribute("featuredReportDonut", featuredReport != null ? buildDonut(featuredReport) : emptyDonut());
        model.addAttribute("featuredReportTrendChart", featuredReport != null ? buildTrendChart(featuredReport) : emptyTrendChart());
        model.addAttribute("featuredScenarioRows", featuredReport != null ? buildScenarioRows(featuredReport).stream().limit(4).toList() : List.of());
        model.addAttribute("catalogHero", buildCatalogHero(featuredAggregate));
        model.addAttribute("catalogStatusRail", buildCatalogStatusRail(catalog, projection.customerSubmissionCount(), certificationSnapshotRows, featuredAggregate));
        model.addAttribute("catalogReportRows", buildCatalogReportRows(projection));
        model.addAttribute("catalogFilterMetadata", buildCatalogFilterMetadata(projection));
        model.addAttribute("catalogTrendSnapshotRows", overviewTrendRows.stream().limit(8).toList());
        model.addAttribute("catalogCertificationSnapshotRows", certificationSnapshotRows);
        model.addAttribute("catalogHasPublishedReports", projection.publishedCount() > 0);
        return "site/benchmark-overview";
    }

    private String familyFromProjection(String routeSlug, Model model, BenchmarkPublicSiteProjection.FamilyProjection projection) {
        PublicBenchmarkSiteView.FamilyCard card = toFamilyCard(new BenchmarkPublicSiteProjection.FamilyAggregate(
                projection.routeSlug(),
                projection.familyKey(),
                projection.publishedCount(),
                projection.submissionReadyCount()));
        BenchmarkPublicSiteProjection.ReportAggregate latestAggregate = findReportAggregate(projection.reportRows(), projection.latestReportSlug());
        PublishedBenchmarkSummary latestReport = latestAggregate != null ? loadPublishedSummary(latestAggregate.slug()) : null;
        List<PublicBenchmarkSiteView.TrendRow> familyTrendRows = toTrendRows(projection.trendRows());
        model.addAttribute("pageTitle", card.title());
        model.addAttribute("familyCard", card);
        model.addAttribute("reports", List.of());
        model.addAttribute("familySummaryCards", familySummaryCards(card, projection, latestAggregate, latestReport));
        model.addAttribute("facetRoutes", facetRoutesFromProjection(projection.families(), routeSlug));
        model.addAttribute("latestReport", latestAggregate != null ? spotlight(latestAggregate) : null);
        model.addAttribute("latestReportDonut", latestReport != null ? buildDonut(latestReport) : emptyDonut());
        model.addAttribute("latestReportTrendChart", latestReport != null ? buildTrendChart(latestReport) : buildTrendChartFromTrendRows(familyTrendRows));
        model.addAttribute("latestScenarioRows", latestReport != null ? buildScenarioRows(latestReport).stream().limit(4).toList() : List.of());
        model.addAttribute("familyClaimLandscape", toClaimLandscapeRows(projection.claimLandscapeRows()));
        model.addAttribute("familyTrendRows", familyTrendRows.stream().limit(6).toList());
        model.addAttribute("methodologySections", methodologySections());
        model.addAttribute("familyReadyRatio", projection.publishedCount() == 0 ? 0.0d : ((double) projection.submissionReadyCount() * 100.0d / projection.publishedCount()));
        model.addAttribute("lensStatusRail", buildLensStatusRail(card, projection, latestAggregate, latestReport));
        model.addAttribute("lensLatestDossier", latestAggregate != null ? spotlight(latestAggregate) : null);
        model.addAttribute("lensClaimDistribution", toClaimLandscapeRows(projection.claimLandscapeRows()));
        model.addAttribute("lensTrendMiniChart", buildTrendChartFromTrendRows(familyTrendRows));
        model.addAttribute("lensReportRows", buildCatalogReportRows(projection));
        model.addAttribute("relatedLensRoutes", facetRoutesFromProjection(projection.families(), routeSlug));
        model.addAttribute("lensHasPublishedReports", !projection.reportRows().isEmpty());
        return "site/benchmark-family";
    }

    private String trendsFromProjection(Model model, BenchmarkPublicSiteProjection.TrendsProjection projection) {
        List<PublicBenchmarkSiteView.LeaderboardRow> leaderboardRows = toLeaderboardRows(projection.leaderboardRows());
        List<PublicBenchmarkSiteView.TrendRow> publishedTrendRows = toTrendRows(projection.publishedTrendRows());
        List<PublicBenchmarkSiteView.TrendRow> customerTrendRows = toTrendRows(projection.customerTrendRows());
        List<PublicBenchmarkSiteView.TrendRow> trendComparisonRows = new ArrayList<>(publishedTrendRows);
        trendComparisonRows.addAll(customerTrendRows);
        model.addAttribute("pageTitle", msg("site.benchmark.facade.trends-title"));
        model.addAttribute("publishedTrendRows", publishedTrendRows);
        model.addAttribute("customerTrendRows", customerTrendRows);
        model.addAttribute("leaderboardRows", leaderboardRows);
        model.addAttribute("trendComparisonRows", trendComparisonRows);
        model.addAttribute("trendSourceBoundary", "First-party published dossiers and customer self-run bundles remain separated on the public appendix surface.");
        return "site/benchmark-trends";
    }

    private String leaderboardFromProjection(Model model, BenchmarkPublicSiteProjection.LeaderboardProjection projection) {
        model.addAttribute("pageTitle", msg("site.benchmark.facade.leaderboard-title"));
        model.addAttribute("leaderboardRows", toLeaderboardRows(projection.leaderboardRows()));
        model.addAttribute("leaderboardSortOptions", List.of(
                new PublicBenchmarkSiteView.CatalogOption("coverage", "Coverage"),
                new PublicBenchmarkSiteView.CatalogOption("ready", "Submission readiness"),
                new PublicBenchmarkSiteView.CatalogOption("source", "Source separation")));
        model.addAttribute("leaderboardSourceBoundary", "Published first-party dossiers and customer self-run bundles remain source-separated in the public comparison surface.");
        return "site/benchmark-leaderboard";
    }

    private BenchmarkPublicSiteProjection.ReportAggregate findReportAggregate(List<BenchmarkPublicSiteProjection.ReportAggregate> reports, String slug) {
        if (reports == null || reports.isEmpty()) {
            return null;
        }
        if (slug == null || slug.isBlank()) {
            return reports.get(0);
        }
        return reports.stream().filter(item -> item.slug().equals(slug)).findFirst().orElse(reports.get(0));
    }

    private PublishedBenchmarkSummary loadPublishedSummary(String slug) {
        if (slug == null || slug.isBlank()) {
            return null;
        }
        try {
            return publicationService.getPublishedArtifact(slug).summary();
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private List<PublicBenchmarkSiteView.MethodologySection> methodologySections() {
        return List.of(
                new PublicBenchmarkSiteView.MethodologySection(
                        "safety-gates",
                        msg("site.benchmark.methodology.section.safety-gates.title"),
                        msg("site.benchmark.methodology.section.safety-gates.summary"),
                        List.of(
                                msg("site.benchmark.methodology.section.safety-gates.p1"),
                                msg("site.benchmark.methodology.section.safety-gates.p2"),
                                msg("site.benchmark.methodology.section.safety-gates.p3"))),
                new PublicBenchmarkSiteView.MethodologySection(
                        "human-agent",
                        msg("site.benchmark.methodology.section.human-agent.title"),
                        msg("site.benchmark.methodology.section.human-agent.summary"),
                        List.of(
                                msg("site.benchmark.methodology.section.human-agent.p1"),
                                msg("site.benchmark.methodology.section.human-agent.p2"),
                                msg("site.benchmark.methodology.section.human-agent.p3"))),
                new PublicBenchmarkSiteView.MethodologySection(
                        "publication",
                        msg("site.benchmark.methodology.section.publication.title"),
                        msg("site.benchmark.methodology.section.publication.summary"),
                        List.of(
                                msg("site.benchmark.methodology.section.publication.p1"),
                                msg("site.benchmark.methodology.section.publication.p2"),
                                msg("site.benchmark.methodology.section.publication.p3"))));
    }

    private List<PublicBenchmarkSiteView.FamilyCard> featuredFamilies(BenchmarkPublicSiteProjection.OverviewProjection projection) {
        return toFamilyCards(projection.families());
    }

    private List<PublicBenchmarkSiteView.FamilyCard> toFamilyCards(List<BenchmarkPublicSiteProjection.FamilyAggregate> families) {
        return families.stream().map(this::toFamilyCard).toList();
    }

    private PublicBenchmarkSiteView.FamilyCard toFamilyCard(BenchmarkPublicSiteProjection.FamilyAggregate family) {
        return new PublicBenchmarkSiteView.FamilyCard(
                family.routeSlug(),
                familyTitle(family.familyKey()),
                familySummary(family.familyKey()),
                family.publishedCount(),
                family.submissionReadyCount());
    }

    private List<PublicBenchmarkSiteView.FacetRouteCard> facetRoutesFromProjection(List<BenchmarkPublicSiteProjection.FamilyAggregate> families, String currentSlug) {
        return families.stream()
                .map(family -> new PublicBenchmarkSiteView.FacetRouteCard(
                        family.routeSlug(),
                        familyTitle(family.familyKey()),
                        familySummary(family.familyKey()),
                        currentSlug != null && routeSlugForFamily(currentSlug).equals(family.routeSlug()),
                        family.publishedCount() > 0 ? family.publishedCount() + " published" : "No published report",
                        family.submissionReadyCount() > 0 ? family.submissionReadyCount() + " ready" : "Publication pending"))
                .toList();
    }

    private PublicBenchmarkSiteView.CatalogHero buildCatalogHero(BenchmarkPublicSiteProjection.ReportAggregate featuredReport) {
        if (featuredReport == null) {
            return null;
        }
        return new PublicBenchmarkSiteView.CatalogHero(
                featuredReport.slug(),
                featuredReport.title(),
                featuredReport.benchmarkVersion(),
                featuredReport.sourceType(),
                "/benchmark/reports/" + featuredReport.slug(),
                "Latest authoritative dossier",
                featuredReport.submissionReady() ? "Submission-ready" : "Published",
                featuredReport.submissionReady() ? "success" : "info",
                featuredReport.coveragePercent(),
                featuredReport.passingOfficialMetricCount(),
                featuredReport.officialMetricCount(),
                featuredReport.claimCount(),
                featuredReport.suiteCount(),
                formatInstantDisplay(featuredReport.publishedAt()));
    }

    private List<PublicBenchmarkSiteView.CatalogStatusItem> buildCatalogStatusRail(BenchmarkPublicationView.CatalogSnapshot catalog,
                                                                                    int customerSubmissionCount,
                                                                                    List<PublicBenchmarkSiteView.CertificationSnapshotRow> certificationRows,
                                                                                    BenchmarkPublicSiteProjection.ReportAggregate featuredReport) {
        int readyProfiles = (int) certificationRows.stream().filter(PublicBenchmarkSiteView.CertificationSnapshotRow::ready).count();
        return List.of(
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "published-reports",
                        "Published reports",
                        countOrState(catalog.publishedCount(), "No published report"),
                        catalog.publishedCount() > 0 ? "success" : "warning",
                        catalog.publishedCount() > 0 ? "Canonical public dossiers are available." : "Publication pending."),
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "current-gate",
                        "Current public gate",
                        featuredReport == null ? "Awaiting publication" : (featuredReport.submissionReady() ? "PASSING" : "REVIEW REQUIRED"),
                        featuredReport == null ? "warning" : (featuredReport.submissionReady() ? "success" : "warning"),
                        featuredReport == null ? "No verified dataset attached." : "Derived from the latest authoritative dossier."),
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "customer-submissions",
                        "Customer submissions",
                        countOrState(customerSubmissionCount, "No submission"),
                        customerSubmissionCount > 0 ? "info" : "warning",
                        customerSubmissionCount > 0 ? "Publication-safe self-run bundles are attached." : "Public intake has no published self-run bundle yet."),
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "certification-ready",
                        "Certification-ready profiles",
                        countOrState(readyProfiles, "No ready profile"),
                        readyProfiles > 0 ? "success" : "warning",
                        readyProfiles > 0 ? "Mapped evidence exists for at least one profile." : "No mapped public dossier is ready for profile evidence yet."));
    }

    private List<PublicBenchmarkSiteView.CatalogReportRow> buildCatalogReportRows(BenchmarkPublicSiteProjection.OverviewProjection projection) {
        return projection.reportRows().stream().map(this::toCatalogReportRow).toList();
    }

    private List<PublicBenchmarkSiteView.CatalogReportRow> buildCatalogReportRows(BenchmarkPublicSiteProjection.FamilyProjection projection) {
        return projection.reportRows().stream().map(this::toCatalogReportRow).toList();
    }

    private PublicBenchmarkSiteView.CatalogReportRow toCatalogReportRow(BenchmarkPublicSiteProjection.ReportAggregate summary) {
        String familyLabel = summary.familyKeys().isEmpty()
                ? "Unclassified"
                : summary.familyKeys().stream().map(this::familyTitle).collect(Collectors.joining(", "));
        return new PublicBenchmarkSiteView.CatalogReportRow(
                summary.slug(),
                summary.title(),
                summary.benchmarkVersion(),
                summary.sourceType(),
                familyLabel,
                "/benchmark/reports/" + summary.slug(),
                summary.coveragePercent(),
                summary.passingOfficialMetricCount(),
                summary.officialMetricCount(),
                summary.claimCount(),
                summary.suiteCount(),
                summary.submissionReady(),
                summary.status(),
                formatInstantDisplay(summary.publishedAt()));
    }

    private PublicBenchmarkSiteView.CatalogFilterMetadata buildCatalogFilterMetadata(BenchmarkPublicSiteProjection.OverviewProjection projection) {
        List<PublicBenchmarkSiteView.CatalogOption> families = projection.filterFamilyKeys().stream()
                .map(family -> new PublicBenchmarkSiteView.CatalogOption(family, familyTitle(family)))
                .toList();
        List<PublicBenchmarkSiteView.CatalogOption> statuses = projection.filterStatuses().stream()
                .map(status -> new PublicBenchmarkSiteView.CatalogOption(status, status.replace('_', ' ')))
                .toList();
        List<PublicBenchmarkSiteView.CatalogOption> sourceTypes = projection.filterSourceTypes().stream()
                .map(sourceType -> new PublicBenchmarkSiteView.CatalogOption(sourceType, sourceType.replace('_', ' ')))
                .toList();
        List<PublicBenchmarkSiteView.CatalogOption> sortOptions = List.of(
                new PublicBenchmarkSiteView.CatalogOption("latest", "Latest publication"),
                new PublicBenchmarkSiteView.CatalogOption("coverage", "Coverage"),
                new PublicBenchmarkSiteView.CatalogOption("claims", "Claim count"),
                new PublicBenchmarkSiteView.CatalogOption("ready", "Submission readiness"));
        return new PublicBenchmarkSiteView.CatalogFilterMetadata(families, statuses, sourceTypes, sortOptions);
    }

    private List<PublicBenchmarkSiteView.CertificationSnapshotRow> toCertificationSnapshotRows(List<BenchmarkPublicSiteProjection.CertificationSnapshotAggregate> aggregates) {
        return aggregates.stream()
                .map(profile -> new PublicBenchmarkSiteView.CertificationSnapshotRow(
                        profile.key(),
                        profile.title(),
                        profile.ready(),
                        profile.matchingReportCount(),
                        profile.latestMappedReport(),
                        profile.readinessBasis(),
                        profile.ready() ? "success" : "warning",
                        profile.requiredSignals()))
                .toList();
    }

    private List<PublicBenchmarkSiteView.FamilyCard> featuredFamilies(List<PublishedBenchmarkSummary> published) {
        return List.of(
                familyCard("human", "human", published),
                familyCard("agent", "agent", published),
                familyCard("protocol", "protocol", published),
                familyCard("verification", "verification", published),
                familyCard("soar", "soar", published),
                familyCard("java", "java-fit", published));
    }

    private PublicBenchmarkSiteView.FamilyCard familyCard(String routeSlug, String familyKey, List<PublishedBenchmarkSummary> published) {
        List<PublishedBenchmarkSummary> matches = published.stream().filter(summary -> matchesFamily(summary, familyKey)).toList();
        int readyCount = (int) matches.stream().filter(PublishedBenchmarkSummary::submissionReady).count();
        return new PublicBenchmarkSiteView.FamilyCard(routeSlug, familyTitle(familyKey), familySummary(familyKey), matches.size(), readyCount);
    }

    private PublicBenchmarkSiteView.CatalogHero buildCatalogHero(PublishedBenchmarkSummary featuredReport) {
        if (featuredReport == null) {
            return null;
        }
        return new PublicBenchmarkSiteView.CatalogHero(
                featuredReport.slug(),
                featuredReport.title(),
                featuredReport.benchmarkVersion(),
                featuredReport.sourceType(),
                "/benchmark/reports/" + featuredReport.slug(),
                "Latest authoritative dossier",
                featuredReport.submissionReady() ? "Submission-ready" : "Published",
                featuredReport.submissionReady() ? "success" : "info",
                featuredReport.overallCoveragePercent(),
                featuredReport.passingOfficialMetricCount(),
                featuredReport.officialMetricCount(),
                safeClaims(featuredReport).size(),
                safeSuites(featuredReport).size(),
                formatInstantDisplay(featuredReport.publishedAt() != null ? featuredReport.publishedAt() : featuredReport.generatedAt()));
    }

    private List<PublicBenchmarkSiteView.CatalogStatusItem> buildCatalogStatusRail(BenchmarkPublicationView.CatalogSnapshot catalog,
                                                                                    int customerSubmissionCount,
                                                                                    List<PartnerCertificationProfileView> certificationProfiles,
                                                                                    PublishedBenchmarkSummary featuredReport) {
        int readyProfiles = (int) certificationProfiles.stream().filter(PartnerCertificationProfileView::ready).count();
        return List.of(
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "published-reports",
                        "Published reports",
                        countOrState(catalog.publishedCount(), "No published report"),
                        catalog.publishedCount() > 0 ? "success" : "warning",
                        catalog.publishedCount() > 0 ? "Canonical public dossiers are available." : "Publication pending."),
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "current-gate",
                        "Current public gate",
                        featuredReport == null ? "Awaiting publication" : (featuredReport.submissionReady() ? "PASSING" : "REVIEW REQUIRED"),
                        featuredReport == null ? "warning" : (featuredReport.submissionReady() ? "success" : "warning"),
                        featuredReport == null ? "No verified dataset attached." : "Derived from the latest authoritative dossier."),
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "customer-submissions",
                        "Customer submissions",
                        countOrState(customerSubmissionCount, "No submission"),
                        customerSubmissionCount > 0 ? "info" : "warning",
                        customerSubmissionCount > 0 ? "Publication-safe self-run bundles are attached." : "Public intake has no published self-run bundle yet."),
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "certification-ready",
                        "Certification-ready profiles",
                        countOrState(readyProfiles, "No ready profile"),
                        readyProfiles > 0 ? "success" : "warning",
                        readyProfiles > 0 ? "Mapped evidence exists for at least one profile." : "No mapped public dossier is ready for profile evidence yet."));
    }

    private List<PublicBenchmarkSiteView.CatalogReportRow> buildCatalogReportRows(List<PublishedBenchmarkSummary> published) {
        return published.stream()
                .sorted(Comparator.comparing(PublishedBenchmarkSummary::generatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .map(summary -> new PublicBenchmarkSiteView.CatalogReportRow(
                        summary.slug(),
                        summary.title(),
                        summary.benchmarkVersion(),
                        summary.sourceType(),
                        catalogFamilyLabel(summary),
                        "/benchmark/reports/" + summary.slug(),
                        summary.overallCoveragePercent(),
                        summary.passingOfficialMetricCount(),
                        summary.officialMetricCount(),
                        safeClaims(summary).size(),
                        safeSuites(summary).size(),
                        summary.submissionReady(),
                        summary.status(),
                        formatInstantDisplay(summary.publishedAt() != null ? summary.publishedAt() : summary.generatedAt())))
                .toList();
    }

    private PublicBenchmarkSiteView.CatalogFilterMetadata buildCatalogFilterMetadata(List<PublishedBenchmarkSummary> published) {
        List<PublicBenchmarkSiteView.CatalogOption> families = published.stream()
                .flatMap(summary -> java.util.stream.Stream.concat(
                        summary.scenarioFamilies().stream().map(this::normalizeFamily),
                        safeFacets(summary).stream().map(BenchmarkFacetResult::key).map(this::normalizeFamily)))
                .distinct()
                .sorted(String.CASE_INSENSITIVE_ORDER)
                .map(family -> new PublicBenchmarkSiteView.CatalogOption(family, familyTitle(family)))
                .toList();
        List<PublicBenchmarkSiteView.CatalogOption> statuses = published.stream()
                .map(summary -> summary.status().name())
                .distinct()
                .sorted(String.CASE_INSENSITIVE_ORDER)
                .map(status -> new PublicBenchmarkSiteView.CatalogOption(status, status.replace('_', ' ')))
                .toList();
        List<PublicBenchmarkSiteView.CatalogOption> sourceTypes = published.stream()
                .map(PublishedBenchmarkSummary::sourceType)
                .distinct()
                .sorted(String.CASE_INSENSITIVE_ORDER)
                .map(sourceType -> new PublicBenchmarkSiteView.CatalogOption(sourceType, sourceType.replace('_', ' ')))
                .toList();
        List<PublicBenchmarkSiteView.CatalogOption> sortOptions = List.of(
                new PublicBenchmarkSiteView.CatalogOption("latest", "Latest publication"),
                new PublicBenchmarkSiteView.CatalogOption("coverage", "Coverage"),
                new PublicBenchmarkSiteView.CatalogOption("claims", "Claim count"),
                new PublicBenchmarkSiteView.CatalogOption("ready", "Submission readiness"));
        return new PublicBenchmarkSiteView.CatalogFilterMetadata(families, statuses, sourceTypes, sortOptions);
    }

    private List<PublicBenchmarkSiteView.CertificationSnapshotRow> buildCertificationSnapshotRows(List<PartnerCertificationProfileView> certificationProfiles) {
        return certificationProfiles.stream()
                .map(profile -> new PublicBenchmarkSiteView.CertificationSnapshotRow(
                        profile.key(),
                        profile.title(),
                        profile.ready(),
                        profile.matchingReportCount(),
                        profile.latestMappedReport(),
                        profile.readinessBasis(),
                        profile.ready() ? "success" : "warning",
                        profile.requiredSignals()))
                .toList();
    }

    private String catalogFamilyLabel(PublishedBenchmarkSummary summary) {
        List<String> families = java.util.stream.Stream.concat(
                        summary.scenarioFamilies().stream().map(this::normalizeFamily),
                        safeFacets(summary).stream().map(BenchmarkFacetResult::key).map(this::normalizeFamily))
                .distinct()
                .map(this::familyTitle)
                .toList();
        return families.isEmpty() ? "Unclassified" : String.join(", ", families);
    }
    private List<PublicBenchmarkSiteView.SummaryCard> overviewSummaryCards(BenchmarkPublicationView.CatalogSnapshot catalog,
                                                                            int customerSubmissionCount,
                                                                            PublishedBenchmarkSummary featuredReport) {
        return List.of(
                new PublicBenchmarkSiteView.SummaryCard(
                        "Published reports",
                        countOrState(catalog.publishedCount(), "No published report"),
                        catalog.publishedCount() > 0
                                ? "Only review-approved and sanitized benchmark artifacts are exposed on the public site."
                                : "The public site stays empty until a benchmark passes internal review and publication safety gates.",
                        catalog.publishedCount() > 0 ? "success" : "warning"),
                new PublicBenchmarkSiteView.SummaryCard(
                        "Catalog health",
                        catalog.reportRootAvailable() ? "READY" : "UNCONFIGURED",
                        catalog.reportRootAvailable() && catalog.reportRoot() != null
                                ? catalog.reportRoot()
                                : "Benchmark publication report root is not currently attached to the public catalog.",
                        catalog.reportRootAvailable() ? "info" : "danger"),
                new PublicBenchmarkSiteView.SummaryCard(
                        "Customer self-run",
                        countOrState(customerSubmissionCount, "No submission"),
                        customerSubmissionCount > 0
                                ? "Customer bundles remain publication-safe and separated from internal enterprise evidence."
                                : "Self-run results appear here only after they pass the publication-safe intake path.",
                        customerSubmissionCount > 0 ? "info" : "warning"),
                new PublicBenchmarkSiteView.SummaryCard(
                        "Current public gate",
                        featuredReport == null
                                ? "Awaiting publication"
                                : (featuredReport.submissionReady() ? "PASSING" : "REVIEW REQUIRED"),
                        featuredReport == null
                                ? "There is no published benchmark report yet, so the site should not imply a measured score."
                                : "Gate state is derived from the latest published report and its official metric coverage.",
                        featuredReport == null ? "warning" : (featuredReport.submissionReady() ? "success" : "danger")));
    }

    private List<PublicBenchmarkSiteView.CatalogStatusItem> buildLensStatusRail(PublicBenchmarkSiteView.FamilyCard card,
                                                                                 BenchmarkPublicSiteProjection.FamilyProjection projection,
                                                                                 BenchmarkPublicSiteProjection.ReportAggregate latestReport,
                                                                                 PublishedBenchmarkSummary latestSummary) {
        Instant latestPublication = latestSummary != null
                ? (latestSummary.publishedAt() != null ? latestSummary.publishedAt() : latestSummary.generatedAt())
                : latestReport != null ? latestReport.publishedAt() : null;
        return List.of(
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "published-reports",
                        "Published reports",
                        countOrState(projection.publishedCount(), "No published report"),
                        projection.publishedCount() > 0 ? "success" : "warning",
                        projection.publishedCount() > 0 ? "This lens routes into published dossiers only." : "Publication pending."),
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "submission-readiness",
                        "Submission readiness",
                        projection.submissionReadyCount() > 0 ? projection.submissionReadyCount() + " ready" : "Publication pending",
                        projection.submissionReadyCount() > 0 ? "success" : "warning",
                        projection.submissionReadyCount() > 0 ? "At least one dossier in this lens is submission-ready." : "No published report in this lens is submission-ready yet."),
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "latest-publication",
                        "Latest publication",
                        latestPublication != null ? DATE_LABEL.format(latestPublication) : "Pending",
                        latestPublication != null ? "info" : "warning",
                        latestPublication != null ? "Latest authoritative dossier timestamp for this lens." : "No public-safe report has been published for this lens yet."),
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "verified-truth",
                        "Verified truth",
                        latestSummary != null && latestSummary.provenance() != null ? latestSummary.provenance().sourceVerifiedCaseCount() + " verified" : "Not published",
                        latestSummary != null && latestSummary.provenance() != null ? "success" : "warning",
                        latestSummary != null && latestSummary.provenance() != null ? "Verification-derived truth is attached to the latest dossier in this lens." : "No verification-derived truth has been published for this lens yet."));
    }

    private List<PublicBenchmarkSiteView.SummaryCard> familySummaryCards(PublicBenchmarkSiteView.FamilyCard card,
                                                                          BenchmarkPublicSiteProjection.FamilyProjection projection,
                                                                          BenchmarkPublicSiteProjection.ReportAggregate latestReport,
                                                                          PublishedBenchmarkSummary latestSummary) {
        int verifiedCaseCount = latestSummary != null && latestSummary.provenance() != null ? latestSummary.provenance().sourceVerifiedCaseCount() : 0;
        int evaluationCaseCount = latestSummary != null && latestSummary.provenance() != null ? latestSummary.provenance().sourceEvaluationCaseCount() : 0;
        Instant latestPublication = latestSummary != null && latestSummary.generatedAt() != null
                ? latestSummary.generatedAt()
                : latestReport != null ? latestReport.publishedAt() : null;
        return List.of(
                new PublicBenchmarkSiteView.SummaryCard(
                        "Published reports",
                        countOrState(card.publishedCount(), "No published report"),
                        card.publishedCount() > 0 ? "This facet is currently backed by published benchmark reports and public-safe artifacts." : "This facet is a discovery lens. It does not become an official result until a report is published.",
                        card.publishedCount() > 0 ? "success" : "warning"),
                new PublicBenchmarkSiteView.SummaryCard(
                        "Submission readiness",
                        projection.submissionReadyCount() > 0 ? projection.submissionReadyCount() + " ready" : "Publication pending",
                        projection.submissionReadyCount() > 0 ? "Submission-ready reports in this lens have already passed review and publication safety checks." : "No published report in this lens is currently marked submission-ready.",
                        projection.submissionReadyCount() > 0 ? "success" : "warning"),
                new PublicBenchmarkSiteView.SummaryCard(
                        "Latest publication",
                        latestPublication != null ? DATE_LABEL.format(latestPublication) : "Pending",
                        latestPublication != null ? "The latest published report is shown below with provenance, suite, and scenario evidence." : "Once a public-safe report is published, the latest run date is surfaced here instead of a placeholder score.",
                        latestPublication != null ? "info" : "warning"),
                new PublicBenchmarkSiteView.SummaryCard(
                        "Verified truth",
                        latestSummary != null ? verifiedCaseCount + " / " + evaluationCaseCount : "Not published",
                        latestSummary != null ? "Verified cases and evaluation cases come from the same truth chain as the public report." : "No verification-derived truth has been published for this facet yet.",
                        latestSummary != null ? "info" : "warning"));
    }

    private List<PublicBenchmarkSiteView.ClaimLandscapeRow> toClaimLandscapeRows(List<BenchmarkPublicSiteProjection.ClaimLandscapeAggregate> rows) {
        return rows.stream()
                .map(row -> new PublicBenchmarkSiteView.ClaimLandscapeRow(
                        row.key(),
                        row.title(),
                        row.publishedReportCount(),
                        row.passingReportCount(),
                        row.averageScore(),
                        row.sourceFamilyKeys().isEmpty() ? "-" : row.sourceFamilyKeys().stream().map(this::familyTitle).collect(Collectors.joining(", "))))
                .toList();
    }

    private PublicBenchmarkSiteView.SpotlightReport spotlight(BenchmarkPublicSiteProjection.ReportAggregate report) {
        if (report == null) {
            return null;
        }
        return new PublicBenchmarkSiteView.SpotlightReport(
                report.slug(),
                report.title(),
                report.benchmarkVersion(),
                report.sourceType(),
                report.coveragePercent(),
                report.passingOfficialMetricCount(),
                report.officialMetricCount(),
                report.failingGateCount(),
                report.submissionReady(),
                report.verifiedCaseCount(),
                report.evaluationCaseCount(),
                report.claimCount(),
                report.suiteCount(),
                report.facetCount());
    }

    private List<PublicBenchmarkSiteView.TrendRow> toTrendRows(List<BenchmarkPublicSiteProjection.TrendAggregate> rows) {
        return rows.stream()
                .map(row -> new PublicBenchmarkSiteView.TrendRow(
                        row.slug(),
                        sourceBucketLabel(row.sourceBucket()),
                        row.title(),
                        row.benchmarkVersion(),
                        row.generatedAt(),
                        row.coveragePercent(),
                        row.passingOfficialMetricCount(),
                        row.officialMetricCount(),
                        row.status()))
                .toList();
    }

    private List<PublicBenchmarkSiteView.LeaderboardRow> toLeaderboardRows(List<BenchmarkPublicSiteProjection.LeaderboardAggregate> rows) {
        return rows.stream()
                .map(row -> new PublicBenchmarkSiteView.LeaderboardRow(
                        row.rank(),
                        sourceBucketLabel(row.sourceBucket()),
                        row.slug(),
                        row.title(),
                        row.benchmarkVersion(),
                        row.coveragePercent(),
                        row.passingOfficialMetricCount(),
                        row.officialMetricCount(),
                        row.submissionReady(),
                        row.status()))
                .toList();
    }

    private String sourceBucketLabel(String sourceBucket) {
        return switch (sourceBucket) {
            case "CUSTOMER_SELF_RUN" -> msg("site.benchmark.common.customer-selfrun");
            case "FIRST_PARTY" -> msg("site.benchmark.common.first-party");
            default -> sourceBucket == null || sourceBucket.isBlank() ? "-" : sourceBucket;
        };
    }

    private String routeSlugForFamily(String family) {
        String normalized = normalizeFamily(family);
        return normalized.equals("java-fit") ? "java" : normalized;
    }

    private PublicBenchmarkSiteView.TrendChartView buildTrendChartFromTrendRows(List<PublicBenchmarkSiteView.TrendRow> rows) {
        List<PublicBenchmarkSiteView.TrendRow> points = rows.stream().limit(12).toList();
        if (points.isEmpty()) {
            return emptyTrendChart();
        }
        double maxCoverage = Math.max(100.0d, points.stream().mapToDouble(PublicBenchmarkSiteView.TrendRow::coveragePercent).max().orElse(100.0d));
        double step = points.size() == 1 ? 0.0d : (TREND_CHART_WIDTH - (TREND_CHART_PADDING_X * 2)) / (points.size() - 1.0d);
        List<PublicBenchmarkSiteView.TrendChartPoint> chartPoints = new ArrayList<>();
        for (int index = 0; index < points.size(); index++) {
            PublicBenchmarkSiteView.TrendRow point = points.get(index);
            double x = TREND_CHART_PADDING_X + (step * index);
            double normalized = maxCoverage <= 0.0d ? 0.0d : (point.coveragePercent() / maxCoverage);
            double y = TREND_CHART_HEIGHT - TREND_CHART_PADDING_Y - (normalized * (TREND_CHART_HEIGHT - (TREND_CHART_PADDING_Y * 2)));
            chartPoints.add(new PublicBenchmarkSiteView.TrendChartPoint(
                    point.benchmarkVersion(),
                    point.generatedAt() != null ? point.generatedAt().toString() : "-",
                    point.coveragePercent(),
                    x,
                    y,
                    point.passingOfficialMetricCount(),
                    Math.max(0, point.officialMetricCount() - point.passingOfficialMetricCount())));
        }
        String polyline = chartPoints.stream()
                .map(point -> String.format(Locale.US, "%.2f,%.2f", point.x(), point.y()))
                .collect(Collectors.joining(" "));
        return new PublicBenchmarkSiteView.TrendChartView(TREND_CHART_WIDTH, TREND_CHART_HEIGHT, maxCoverage, polyline, chartPoints);
    }

    private List<PublicBenchmarkSiteView.CatalogStatusItem> buildLensStatusRail(PublicBenchmarkSiteView.FamilyCard card,
                                                                                 List<PublishedBenchmarkSummary> reports,
                                                                                 PublishedBenchmarkSummary latestReport) {
        int readyCount = (int) reports.stream().filter(PublishedBenchmarkSummary::submissionReady).count();
        return List.of(
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "published-reports",
                        "Published reports",
                        countOrState(reports.size(), "No published report"),
                        reports.isEmpty() ? "warning" : "success",
                        reports.isEmpty() ? "Publication pending." : "This lens routes into published dossiers only."),
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "submission-readiness",
                        "Submission readiness",
                        readyCount > 0 ? readyCount + " ready" : "Publication pending",
                        readyCount > 0 ? "success" : "warning",
                        readyCount > 0 ? "At least one dossier in this lens is submission-ready." : "No published report in this lens is submission-ready yet."),
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "latest-publication",
                        "Latest publication",
                        latestReport != null ? DATE_LABEL.format(latestReport.publishedAt() != null ? latestReport.publishedAt() : latestReport.generatedAt()) : "Pending",
                        latestReport != null ? "info" : "warning",
                        latestReport != null ? "Latest authoritative dossier timestamp for this lens." : "No public-safe report has been published for this lens yet."),
                new PublicBenchmarkSiteView.CatalogStatusItem(
                        "verified-truth",
                        "Verified truth",
                        latestReport != null && latestReport.provenance() != null ? latestReport.provenance().sourceVerifiedCaseCount() + " verified" : "Not published",
                        latestReport != null && latestReport.provenance() != null ? "success" : "warning",
                        latestReport != null && latestReport.provenance() != null ? "Verification-derived truth is attached to the latest dossier in this lens." : "No verification-derived truth has been published for this lens yet."));
    }
    private List<PublicBenchmarkSiteView.SummaryCard> familySummaryCards(PublicBenchmarkSiteView.FamilyCard card,
                                                                          List<PublishedBenchmarkSummary> reports,
                                                                          PublishedBenchmarkSummary latestReport) {
        int readyCount = (int) reports.stream().filter(PublishedBenchmarkSummary::submissionReady).count();
        int verifiedCaseCount = latestReport != null && latestReport.provenance() != null ? latestReport.provenance().sourceVerifiedCaseCount() : 0;
        int evaluationCaseCount = latestReport != null && latestReport.provenance() != null ? latestReport.provenance().sourceEvaluationCaseCount() : 0;
        return List.of(
                new PublicBenchmarkSiteView.SummaryCard(
                        "Published reports",
                        countOrState(card.publishedCount(), "No published report"),
                        card.publishedCount() > 0
                                ? "This facet is currently backed by published benchmark reports and public-safe artifacts."
                                : "This facet is a discovery lens. It does not become an official result until a report is published.",
                        card.publishedCount() > 0 ? "success" : "warning"),
                new PublicBenchmarkSiteView.SummaryCard(
                        "Submission readiness",
                        readyCount > 0 ? readyCount + " ready" : "Publication pending",
                        readyCount > 0
                                ? "Submission-ready reports in this lens have already passed review and publication safety checks."
                                : "No published report in this lens is currently marked submission-ready.",
                        readyCount > 0 ? "success" : "warning"),
                new PublicBenchmarkSiteView.SummaryCard(
                        "Latest publication",
                        latestReport != null && latestReport.generatedAt() != null ? DATE_LABEL.format(latestReport.generatedAt()) : "Pending",
                        latestReport != null
                                ? "The latest published report is shown below with provenance, suite, and scenario evidence."
                                : "Once a public-safe report is published, the latest run date is surfaced here instead of a placeholder score.",
                        latestReport != null ? "info" : "warning"),
                new PublicBenchmarkSiteView.SummaryCard(
                        "Verified truth",
                        latestReport != null ? verifiedCaseCount + " / " + evaluationCaseCount : "Not published",
                        latestReport != null
                                ? "Verified cases and evaluation cases come from the same truth chain as the public report."
                                : "No verification-derived truth has been published for this facet yet.",
                        latestReport != null ? "info" : "warning"));
    }

    private List<PublicBenchmarkSiteView.FacetRouteCard> facetRoutes(List<PublishedBenchmarkSummary> published, String currentSlug) {
        return featuredFamilies(published).stream()
                .map(card -> new PublicBenchmarkSiteView.FacetRouteCard(
                        card.slug(),
                        card.title(),
                        card.summary(),
                        currentSlug != null && normalizeFamily(card.slug()).equals(normalizeFamily(currentSlug)),
                        card.publishedCount() > 0 ? card.publishedCount() + " published" : "No published report",
                        card.submissionReadyCount() > 0 ? card.submissionReadyCount() + " ready" : "Publication pending"))
                .toList();
    }

    private PublicBenchmarkSiteView.SpotlightReport spotlight(PublishedBenchmarkSummary report) {
        if (report == null) {
            return null;
        }
        int verifiedCaseCount = report.provenance() != null ? report.provenance().sourceVerifiedCaseCount() : 0;
        int evaluationCaseCount = report.provenance() != null ? report.provenance().sourceEvaluationCaseCount() : 0;
        return new PublicBenchmarkSiteView.SpotlightReport(
                report.slug(),
                report.title(),
                report.benchmarkVersion(),
                report.sourceType(),
                report.overallCoveragePercent(),
                report.passingOfficialMetricCount(),
                report.officialMetricCount(),
                report.failingOfficialMetricCount(),
                report.submissionReady(),
                verifiedCaseCount,
                evaluationCaseCount,
                safeClaims(report).size(),
                safeSuites(report).size(),
                safeFacets(report).size());
    }

    private PublicBenchmarkSiteView.DossierHero buildDossierHero(PublishedBenchmarkSummary report) {
        return new PublicBenchmarkSiteView.DossierHero(
                report.slug(),
                report.title(),
                report.benchmarkVersion(),
                report.sourceType(),
                report.submissionReady() ? "Submission-ready" : "Published",
                report.submissionReady() ? "success" : "info",
                "Canonical benchmark dossier for external review.",
                report.submissionReady(),
                report.overallCoveragePercent(),
                safeClaims(report).size(),
                safeSuites(report).size(),
                formatInstantDisplay(report.publishedAt() != null ? report.publishedAt() : report.generatedAt()));
    }

    private PublicBenchmarkSiteView.DossierProvenanceStrip buildDossierProvenance(PublishedBenchmarkSummary report,
                                                                                   PublishedBenchmarkManifest manifest) {
        return new PublicBenchmarkSiteView.DossierProvenanceStrip(
                report.provenance() != null ? report.provenance().sourceVerifiedCaseCount() : 0,
                report.provenance() != null ? report.provenance().sourceEvaluationCaseCount() : 0,
                report.provenance() != null ? report.provenance().verifiedMetricCount() : 0,
                report.provenance() != null ? report.provenance().replayCoverageRate() : 0.0d,
                report.provenance() != null ? report.provenance().assuranceCoverageRate() : 0.0d,
                manifest != null ? manifest.methodologyVersion() : null,
                manifest != null ? manifest.sanitizationProfileVersion() : null,
                manifest != null ? manifest.suiteVersion() : null,
                formatInstantDisplay(report.provenance() != null ? report.provenance().lastVerifiedAt() : null));
    }

    private PublicBenchmarkSiteView.DossierOfficialGateSummary buildDossierOfficialGate(PublishedBenchmarkSummary report) {
        return new PublicBenchmarkSiteView.DossierOfficialGateSummary(
                report.officialMetricCount(),
                report.passingOfficialMetricCount(),
                report.failingOfficialMetricCount(),
                safeStrings(report.missingOfficialMetrics()),
                report.submissionReady());
    }

    private PublicBenchmarkSiteView.DossierExploitWindowSummary buildDossierExploitWindow(PublishedBenchmarkSummary report) {
        ExploitWindowControlResult exploitWindowResult = report.exploitWindowResult();
        boolean present = exploitWindowResult != null && exploitWindowResult.present();
        return new PublicBenchmarkSiteView.DossierExploitWindowSummary(
                present,
                safeExploitClaims(report).size(),
                safeExploitCases(report).size(),
                present ? exploitWindowResult.averageSignalToControlLatencyMillis() : 0L,
                present ? exploitWindowResult.maxSignalToControlLatencyMillis() : 0L,
                present ? exploitWindowResult.controlCoverageRate() : 0.0d,
                present ? exploitWindowResult.permitContinuityRate() : 0.0d);
    }
    private PublicBenchmarkSiteView.ReportExecutiveView buildReportExecutive(PublishedBenchmarkSummary report) {
        int verifiedCaseCount = report.provenance() != null ? report.provenance().sourceVerifiedCaseCount() : 0;
        int evaluationCaseCount = report.provenance() != null ? report.provenance().sourceEvaluationCaseCount() : 0;
        int passingClaims = (int) safeClaims(report).stream().filter(BenchmarkClaimResult::pass).count();
        int readyFacets = (int) safeFacets(report).stream().filter(BenchmarkFacetResult::publicationReady).count();
        int suiteCount = safeSuites(report).size();
        String statusTone = report.submissionReady()
                ? "success"
                : (report.failingOfficialMetricCount() > 0 || !safeStrings(report.missingOfficialMetrics()).isEmpty() ? "danger" : "warning");
        String statusLabel = report.submissionReady() ? "Submission Ready" : "Publication Hold";
        String summary = report.submissionReady()
                ? "This publication-safe benchmark report cleared the current external release gate. Its official metrics, claims, suites, and truth provenance can be reviewed as a formal CONTEXA scorecard."
                : "This public benchmark artifact remains visible for review, but it should be read as a scorecard under hold until failing gates or missing official metrics are resolved.";
        String readerGuidance = "Use this page as the canonical public reading path. It summarizes verification-derived truth, normalized evaluation cases, benchmark claims, and public-safe evidence without exposing internal tenant traces.";
        return new PublicBenchmarkSiteView.ReportExecutiveView(
                statusLabel,
                statusTone,
                summary,
                readerGuidance,
                List.of(
                        new PublicBenchmarkSiteView.ReportDocketItem("Publication status", statusLabel, "Current external release gate for this public benchmark."),
                        new PublicBenchmarkSiteView.ReportDocketItem("Source type", report.sourceType(), "Origin of the published benchmark bundle."),
                        new PublicBenchmarkSiteView.ReportDocketItem("Generated", formatInstantDisplay(report.generatedAt()), "Time the public-safe artifact set was assembled."),
                        new PublicBenchmarkSiteView.ReportDocketItem("Published", formatInstantDisplay(report.publishedAt()), "Time the report entered the public catalog."),
                        new PublicBenchmarkSiteView.ReportDocketItem("Methodology", report.provenance() != null ? report.provenance().methodologyVersion() : "-", "Fixed methodology profile applied to evaluation and publication."),
                        new PublicBenchmarkSiteView.ReportDocketItem("Sanitization", report.provenance() != null ? report.provenance().sanitizationProfileVersion() : "-", "Public-scope sanitization profile used for this release."),
                        new PublicBenchmarkSiteView.ReportDocketItem("Truth lineage", verifiedCaseCount + " verified / " + evaluationCaseCount + " evaluation", "Source cases from the unified truth chain behind this scorecard."),
                        new PublicBenchmarkSiteView.ReportDocketItem("Public scope", safeClaims(report).size() + " claims / " + readyFacets + " ready facets", "Public assertions and lenses exposed by this report.")),
                List.of(
                        new PublicBenchmarkSiteView.ReportKpiCard("Overall coverage", formatPercentDisplay(report.overallCoveragePercent()), "Official passing metrics over the declared official metric set.", statusTone),
                        new PublicBenchmarkSiteView.ReportKpiCard("Claims passing", passingClaims + " / " + safeClaims(report).size(), "Public product claims that currently clear their evaluation gate.", passingClaims == safeClaims(report).size() && !safeClaims(report).isEmpty() ? "success" : statusTone),
                        new PublicBenchmarkSiteView.ReportKpiCard("Verified truth cases", Integer.toString(verifiedCaseCount), "Verification truth cases feeding the published scorecard.", "info"),
                        new PublicBenchmarkSiteView.ReportKpiCard("Evaluation suites", suiteCount + " suites", "Verification-derived suite families contributing to the benchmark result.", suiteCount > 0 ? "info" : "warning")));
    }

    private List<PublicBenchmarkSiteView.ClaimHighlightCard> buildClaimHighlights(PublishedBenchmarkSummary report) {
        return safeClaims(report).stream()
                .sorted(Comparator.comparing(BenchmarkClaimResult::score).reversed()
                        .thenComparing(BenchmarkClaimResult::title, String.CASE_INSENSITIVE_ORDER))
                .limit(4)
                .map(claim -> new PublicBenchmarkSiteView.ClaimHighlightCard(
                        claim.key(),
                        claim.title(),
                        claim.score(),
                        claim.pass(),
                        claim.supportingSuites().isEmpty() ? "-" : String.join(", ", claim.supportingSuites()),
                        claim.passingEvaluationCaseCount(),
                        claim.sourceEvaluationCaseCount()))
                .toList();
    }
    private List<PublicBenchmarkSiteView.SummaryCard> buildExploitSummaryCards(PublishedBenchmarkSummary report) {
        ExploitWindowControlResult result = report.exploitWindowResult();
        if (result == null || !result.present()) {
            return List.of(
                    new PublicBenchmarkSiteView.SummaryCard("Source exposure signals", "No published signal", "This report does not yet carry Glasswing-Bridge exploit-window proof cases.", "warning"),
                    new PublicBenchmarkSiteView.SummaryCard("Applied controls", "Not published", "Runtime compensating control evidence appears only after verified exposure cases are attached.", "warning"),
                    new PublicBenchmarkSiteView.SummaryCard("Control latency", "Not published", "Signal-to-control latency requires verified exposure signals and applied runtime controls.", "warning"),
                    new PublicBenchmarkSiteView.SummaryCard("Proof completeness", "Not published", "Proof completeness is calculated only when controls and verification-safe evidence are both present.", "warning"));
        }
        return List.of(
                new PublicBenchmarkSiteView.SummaryCard("Source exposure signals", Integer.toString(result.exposureSignalCount()), "Canonical upstream findings that were correlated into the public report.", result.exposureSignalCount() > 0 ? "info" : "warning"),
                new PublicBenchmarkSiteView.SummaryCard("Applied controls", Integer.toString(result.appliedControlCount()), "Runtime compensating controls executed or registered against the exploit window.", result.appliedControlCount() > 0 ? "success" : "warning"),
                new PublicBenchmarkSiteView.SummaryCard("Control latency", formatLatencyDisplay(result.averageSignalToControlLatencyMillis()), "Average time between exposure detection and runtime control application.", result.averageSignalToControlLatencyMillis() > 0 ? "info" : "warning"),
                new PublicBenchmarkSiteView.SummaryCard("Proof completeness", formatPercentDisplay(result.proofCompletenessRate() * 100.0d), "Signals with control coverage, correlation, and verification-safe evidence.", result.proofCompletenessRate() >= 0.70d ? "success" : "warning"));
    }

    private List<PublicBenchmarkSiteView.ClaimLandscapeRow> buildClaimLandscape(List<PublishedBenchmarkSummary> reports) {
        Map<String, ClaimLandscapeAccumulator> aggregate = new java.util.LinkedHashMap<>();
        for (PublishedBenchmarkSummary report : reports) {
            String families = report.scenarioFamilies() == null || report.scenarioFamilies().isEmpty()
                    ? "-"
                    : String.join(", ", report.scenarioFamilies());
            for (BenchmarkClaimResult claim : safeClaims(report)) {
                ClaimLandscapeAccumulator accumulator = aggregate.computeIfAbsent(
                        claim.key(),
                        ignored -> new ClaimLandscapeAccumulator(claim.title()));
                accumulator.publishedReportCount++;
                if (claim.pass()) {
                    accumulator.passingReportCount++;
                }
                accumulator.totalScore += claim.score();
                accumulator.sourceFamilies.add(families);
            }
        }
        return aggregate.entrySet().stream()
                .map(entry -> new PublicBenchmarkSiteView.ClaimLandscapeRow(
                        entry.getKey(),
                        entry.getValue().title,
                        entry.getValue().publishedReportCount,
                        entry.getValue().passingReportCount,
                        entry.getValue().publishedReportCount == 0 ? 0.0d : entry.getValue().totalScore / entry.getValue().publishedReportCount,
                        entry.getValue().sourceFamilies.isEmpty() ? "-" : String.join(", ", entry.getValue().sourceFamilies)))
                .sorted(Comparator.comparing(PublicBenchmarkSiteView.ClaimLandscapeRow::averageScore).reversed()
                        .thenComparing(PublicBenchmarkSiteView.ClaimLandscapeRow::title, String.CASE_INSENSITIVE_ORDER))
                .limit(8)
                .toList();
    }

    private List<PublicBenchmarkSiteView.ReportClaimScoreRow> buildReportClaimScoreRows(PublishedBenchmarkSummary report) {
        return safeClaims(report).stream()
                .sorted(Comparator.comparing(BenchmarkClaimResult::score).reversed()
                        .thenComparing(BenchmarkClaimResult::title, String.CASE_INSENSITIVE_ORDER))
                .map(claim -> new PublicBenchmarkSiteView.ReportClaimScoreRow(
                        claim.key(),
                        claim.title(),
                        claim.score(),
                        claim.pass(),
                        claim.supportingSuites().isEmpty() ? "-" : String.join(", ", claim.supportingSuites()),
                        claim.passingEvaluationCaseCount(),
                        claim.sourceEvaluationCaseCount(),
                        claim.failingGates() == null ? List.of() : claim.failingGates()))
                .toList();
    }

    private List<PublicBenchmarkSiteView.ReportScenarioRow> buildScenarioRows(PublishedBenchmarkSummary report) {
        return safeScenarioRows(report).stream()
                .map(row -> {
                    double denominator = Math.max(Math.abs(row.expected()), 1.0d);
                    double deltaPercent = ((row.actual() - row.expected()) / denominator) * 100.0d;
                    return new PublicBenchmarkSiteView.ReportScenarioRow(
                            row.key(),
                            row.label(),
                            row.category(),
                            row.actual(),
                            row.expected(),
                            deltaPercent,
                            row.pass(),
                            safeStrings(row.claimKeys()),
                            safeStrings(row.suiteKeys()),
                            safeValue(row.deviationClass()));
                })
                .toList();
    }

    private List<PublicBenchmarkSiteView.ReportTrendComparisonRow> buildTrendComparisonRows(PublishedBenchmarkSummary report) {
        return safeTrendPoints(report).stream()
                .map(point -> new PublicBenchmarkSiteView.ReportTrendComparisonRow(
                        point.label(),
                        safeValue(point.versionMarker()),
                        safeValue(point.milestoneLabel()),
                        safeValue(point.sourceLabel()),
                        point.generatedAt() == null ? "-" : formatInstantDisplay(point.generatedAt()),
                        point.coveragePercent(),
                        point.deltaFromPrevious(),
                        point.passingOfficialMetricCount(),
                        point.failingOfficialMetricCount()))
                .toList();
    }

    private List<PublicBenchmarkSiteView.SummaryCard> buildReportGateSummaryCards(PublishedBenchmarkSummary report) {
        int passing = Math.max(report.passingOfficialMetricCount(), 0);
        int failing = Math.max(report.failingOfficialMetricCount(), 0);
        int missing = safeStrings(report.missingOfficialMetrics()).size();
        return List.of(
                new PublicBenchmarkSiteView.SummaryCard("Passing metrics", Integer.toString(passing), "Official metrics that cleared the external publication gate.", passing > 0 ? "success" : "warning"),
                new PublicBenchmarkSiteView.SummaryCard("Failing metrics", Integer.toString(failing), "Metrics that currently hold the report in review or require explanation.", failing > 0 ? "danger" : "success"),
                new PublicBenchmarkSiteView.SummaryCard("Missing metrics", Integer.toString(missing), "Required official metrics that were not published with this artifact.", missing > 0 ? "warning" : "success"),
                new PublicBenchmarkSiteView.SummaryCard("Observed official metrics", report.observedOfficialMetricCount() + " / " + report.officialMetricCount(), "Observed metrics compared with the declared official metric set.", report.observedOfficialMetricCount() > 0 ? "info" : "warning"));
    }

    private List<PublicBenchmarkSiteView.ReportArtifactCard> buildReportArtifactCards(String slug, PublishedBenchmarkManifest manifest) {
        return List.of(
                new PublicBenchmarkSiteView.ReportArtifactCard("summary.json", "/benchmark/reports/" + slug + "/summary.json", "Public summary contract containing claims, suites, scenarios, trends, and provenance-safe aggregates.", artifactIdentity(manifest, "summary.json")),
                new PublicBenchmarkSiteView.ReportArtifactCard("chart-data.json", "/benchmark/reports/" + slug + "/chart-data.json", "Machine-readable grouped, donut, trend, and heatmap dataset for the published report.", artifactIdentity(manifest, "chart-data.json")),
                new PublicBenchmarkSiteView.ReportArtifactCard("manifest.json", "/benchmark/reports/" + slug + "/manifest.json", "Publication manifest describing the released files and benchmark provenance envelope.", manifestIdentity(manifest)),
                new PublicBenchmarkSiteView.ReportArtifactCard("report.html", "/benchmark/reports/" + slug + "/html", "Printable HTML benchmark dossier for external review and archival reading.", artifactIdentity(manifest, "report.html")),
                new PublicBenchmarkSiteView.ReportArtifactCard("report.pdf", "/benchmark/reports/" + slug + "/pdf", "Printable PDF benchmark dossier aligned to the same public report structure.", artifactIdentity(manifest, "report.pdf")));
    }

    private List<PublicBenchmarkSiteView.ReportConstraint> buildReportConstraints(PublishedBenchmarkSummary report, PublishedBenchmarkManifest manifest) {
        return List.of(
                new PublicBenchmarkSiteView.ReportConstraint("Public boundary", "Only publication-approved artifacts are exposed here. Raw tenant traces, internal request payloads, and enterprise-only evidence remain outside the public report.", "info"),
                new PublicBenchmarkSiteView.ReportConstraint("Methodology lock", "This report must be interpreted together with methodology " + safeValue(manifest != null ? manifest.methodologyVersion() : null) + ", sanitization " + safeValue(manifest != null ? manifest.sanitizationProfileVersion() : null) + ", and suite version " + safeValue(manifest != null ? manifest.suiteVersion() : null) + ".", "info"),
                new PublicBenchmarkSiteView.ReportConstraint("Metric interpretation", "Missing or failing official metrics are explicit hold conditions. They are not rendered as zero, and they remain visible in the public scorecard.", (report.failingOfficialMetricCount() > 0 || !safeStrings(report.missingOfficialMetrics()).isEmpty()) ? "warning" : "success"),
                new PublicBenchmarkSiteView.ReportConstraint("Exploit-window proof scope", report.exploitWindowResult() != null && report.exploitWindowResult().present() ? "Exploit-window proof rows are present only when canonical exposure signals, runtime controls, and verification-safe evidence are attached to the report." : "Exploit-window proof is intentionally absent until verified exposure-to-control evidence is attached.", report.exploitWindowResult() != null && report.exploitWindowResult().present() ? "success" : "warning"));
    }

    private String manifestIdentity(PublishedBenchmarkManifest manifest) {
        if (manifest == null) {
            return "Manifest unavailable";
        }
        if (manifest.manifestIdentity() != null && !manifest.manifestIdentity().isBlank()) {
            return manifest.manifestIdentity();
        }
        return String.format(Locale.US,
                "%s | %s | generated %s | published %s",
                safeValue(manifest.slug()),
                safeValue(manifest.benchmarkVersion()),
                formatInstantDisplay(manifest.generatedAt()),
                formatInstantDisplay(manifest.publishedAt()));
    }

    private String artifactIdentity(PublishedBenchmarkManifest manifest, String artifactName) {
        String digest = manifest != null ? manifest.digestFor(artifactName) : null;
        if (digest == null || digest.isBlank()) {
            return manifestIdentity(manifest);
        }
        return manifestIdentity(manifest) + " | SHA-256 " + digest.substring(0, Math.min(12, digest.length()));
    }

    private String safeValue(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }

    private String formatPercentDisplay(double value) {
        return String.format(Locale.US, "%.2f%%", value);
    }

    private String formatLatencyDisplay(long millis) {
        if (millis < 0L) {
            return "-";
        }
        if (millis < 1000L) {
            return millis + " ms";
        }
        if (millis < 60000L) {
            return String.format(Locale.US, "%.2f s", millis / 1000.0d);
        }
        return String.format(Locale.US, "%.2f min", millis / 60000.0d);
    }

    private String formatInstantDisplay(java.time.Instant instant) {
        return instant == null ? "-" : DATE_TIME_LABEL.format(instant);
    }

    private String familyTitle(String slug) {
        String normalized = normalizeFamily(slug);
        String key = "site.benchmark.family.title." + normalized;
        return messageSource.getMessage(key, null, normalized.toUpperCase(Locale.ROOT), LocaleContextHolder.getLocale());
    }

    private String familySummary(String slug) {
        String normalized = normalizeFamily(slug);
        String key = "site.benchmark.family.summary." + normalized;
        return messageSource.getMessage(key, null, msg("site.benchmark.family.summary.default"), LocaleContextHolder.getLocale());
    }

    private List<PublicBenchmarkSiteView.TrendRow> buildTrendRows(String sourceLabel, List<PublishedBenchmarkSummary> summaries) {
        return summaries.stream()
                .sorted(Comparator.comparing(PublishedBenchmarkSummary::generatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .map(summary -> new PublicBenchmarkSiteView.TrendRow(
                        summary.slug(),
                        sourceLabel,
                        summary.title(),
                        summary.benchmarkVersion(),
                        summary.generatedAt(),
                        summary.overallCoveragePercent(),
                        summary.passingOfficialMetricCount(),
                        summary.officialMetricCount(),
                        summary.status()))
                .toList();
    }

    private List<PublicBenchmarkSiteView.LeaderboardRow> buildLeaderboardRows(List<PublishedBenchmarkSummary> firstParty,
                                                                              List<PublishedBenchmarkSummary> customerSubmissions) {
        List<PublicBenchmarkSiteView.LeaderboardRow> rows = new ArrayList<>();
        List<PublicBenchmarkSiteView.LeaderboardRow> unsorted = new ArrayList<>();
        firstParty.forEach(summary -> unsorted.add(toLeaderboardRow(msg("site.benchmark.common.first-party"), summary)));
        customerSubmissions.forEach(summary -> unsorted.add(toLeaderboardRow(msg("site.benchmark.common.customer-selfrun"), summary)));
        List<PublicBenchmarkSiteView.LeaderboardRow> sorted = unsorted.stream()
                .sorted(Comparator.comparing(PublicBenchmarkSiteView.LeaderboardRow::coveragePercent).reversed()
                        .thenComparing(PublicBenchmarkSiteView.LeaderboardRow::submissionReady, Comparator.reverseOrder())
                        .thenComparing(PublicBenchmarkSiteView.LeaderboardRow::title, String.CASE_INSENSITIVE_ORDER))
                .toList();
        IntStream.range(0, sorted.size()).forEach(index -> {
            PublicBenchmarkSiteView.LeaderboardRow row = sorted.get(index);
            rows.add(new PublicBenchmarkSiteView.LeaderboardRow(
                    index + 1,
                    row.sourceLabel(),
                    row.slug(),
                    row.title(),
                    row.benchmarkVersion(),
                    row.coveragePercent(),
                    row.passingOfficialMetricCount(),
                    row.officialMetricCount(),
                    row.submissionReady(),
                    row.status()));
        });
        return rows;
    }

    private PublicBenchmarkSiteView.LeaderboardRow toLeaderboardRow(String sourceLabel, PublishedBenchmarkSummary summary) {
        return new PublicBenchmarkSiteView.LeaderboardRow(
                0,
                sourceLabel,
                summary.slug(),
                summary.title(),
                summary.benchmarkVersion(),
                summary.overallCoveragePercent(),
                summary.passingOfficialMetricCount(),
                summary.officialMetricCount(),
                summary.submissionReady(),
                summary.status());
    }

    private boolean matchesFamily(PublishedBenchmarkSummary summary, String family) {
        String normalized = normalizeFamily(family);
        if (summary.facets() != null && summary.facets().stream().map(item -> normalizeFamily(item.key())).anyMatch(normalized::equals)) {
            return true;
        }
        if (summary.scenarioFamilies().stream().map(this::normalizeFamily).anyMatch(normalized::equals)) {
            return true;
        }
        String aggregate = (summary.slug() + " " + summary.title() + " " + String.join(" ", summary.availableSourceReports())).toLowerCase(Locale.ROOT);
        if (normalized.equals("java-fit")) {
            return aggregate.contains("spring") || aggregate.contains("java");
        }
        return aggregate.contains(normalized);
    }

    private String normalizeFamily(String family) {
        if (family == null) {
            return "";
        }
        String normalized = family.trim().toLowerCase(Locale.ROOT);
        if (normalized.equals("java")) {
            return "java-fit";
        }
        return normalized;
    }

    private PublicBenchmarkSiteView.ReportDonutView buildDonut(PublishedBenchmarkSummary report) {
        int passing = Math.max(report.passingOfficialMetricCount(), 0);
        int failing = Math.max(report.failingOfficialMetricCount(), 0);
        int missing = Math.max(safeStrings(report.missingOfficialMetrics()).size(), 0);
        int total = Math.max(passing + failing + missing, 1);

        List<PublicBenchmarkSiteView.DonutLegendItem> segments = List.of(
                new PublicBenchmarkSiteView.DonutLegendItem(msg("site.benchmark.report.donut.passing"), passing, "success", "#06d6a0"),
                new PublicBenchmarkSiteView.DonutLegendItem(msg("site.benchmark.report.donut.failing"), failing, "danger", "#e63946"),
                new PublicBenchmarkSiteView.DonutLegendItem(msg("site.benchmark.report.donut.missing"), missing, "warning", "#ffd166")
        );

        double start = 0.0d;
        List<String> stops = new ArrayList<>();
        for (PublicBenchmarkSiteView.DonutLegendItem segment : segments) {
            double sweep = segment.value() <= 0 ? 0.0d : (segment.value() * 100.0d / total);
            double end = Math.min(100.0d, start + sweep);
            stops.add(String.format(Locale.US, "%s %.2f%% %.2f%%", segment.color(), start, end));
            start = end;
        }
        if (stops.stream().allMatch(stop -> stop.endsWith("0.00% 0.00%"))) {
            stops = List.of("#33506b 0% 100%");
        }
        return new PublicBenchmarkSiteView.ReportDonutView("conic-gradient(" + String.join(", ", stops) + ")", total, segments);
    }

    private PublicBenchmarkSiteView.ReportDonutView emptyDonut() {
        return new PublicBenchmarkSiteView.ReportDonutView(
                "conic-gradient(#33506b 0% 100%)",
                0,
                List.of(
                        new PublicBenchmarkSiteView.DonutLegendItem("Published", 0, "info", "#0ea5e9"),
                        new PublicBenchmarkSiteView.DonutLegendItem("Pending", 0, "warning", "#ffd166")));
    }

    private PublicBenchmarkSiteView.TrendChartView buildTrendChart(PublishedBenchmarkSummary report) {
        List<PublishedBenchmarkTrendView.Point> points = safeTrendPoints(report);
        if (points.isEmpty()) {
            return emptyTrendChart();
        }

        double maxCoverage = Math.max(100.0d, points.stream().mapToDouble(PublishedBenchmarkTrendView.Point::coveragePercent).max().orElse(100.0d));
        double step = points.size() == 1 ? 0.0d : (TREND_CHART_WIDTH - (TREND_CHART_PADDING_X * 2)) / (points.size() - 1.0d);
        List<PublicBenchmarkSiteView.TrendChartPoint> chartPoints = new ArrayList<>();
        for (int index = 0; index < points.size(); index++) {
            PublishedBenchmarkTrendView.Point point = points.get(index);
            double x = TREND_CHART_PADDING_X + (step * index);
            double normalized = maxCoverage <= 0.0d ? 0.0d : (point.coveragePercent() / maxCoverage);
            double y = TREND_CHART_HEIGHT - TREND_CHART_PADDING_Y - (normalized * (TREND_CHART_HEIGHT - (TREND_CHART_PADDING_Y * 2)));
            chartPoints.add(new PublicBenchmarkSiteView.TrendChartPoint(
                    point.label(),
                    point.generatedAt() != null ? point.generatedAt().toString() : "-",
                    point.coveragePercent(),
                    x,
                    y,
                    point.passingOfficialMetricCount(),
                    point.failingOfficialMetricCount()));
        }
        String polyline = chartPoints.stream()
                .map(point -> String.format(Locale.US, "%.2f,%.2f", point.x(), point.y()))
                .collect(Collectors.joining(" "));
        return new PublicBenchmarkSiteView.TrendChartView(TREND_CHART_WIDTH, TREND_CHART_HEIGHT, maxCoverage, polyline, chartPoints);
    }

    private PublicBenchmarkSiteView.TrendChartView buildTrendChart(List<PublishedBenchmarkSummary> summaries) {
        List<PublishedBenchmarkSummary> points = summaries.stream()
                .sorted(Comparator.comparing(PublishedBenchmarkSummary::generatedAt, Comparator.nullsLast(Comparator.naturalOrder())))
                .limit(12)
                .toList();
        if (points.isEmpty()) {
            return emptyTrendChart();
        }
        double maxCoverage = Math.max(100.0d, points.stream().mapToDouble(PublishedBenchmarkSummary::overallCoveragePercent).max().orElse(100.0d));
        double step = points.size() == 1 ? 0.0d : (TREND_CHART_WIDTH - (TREND_CHART_PADDING_X * 2)) / (points.size() - 1.0d);
        List<PublicBenchmarkSiteView.TrendChartPoint> chartPoints = new ArrayList<>();
        for (int index = 0; index < points.size(); index++) {
            PublishedBenchmarkSummary point = points.get(index);
            double x = TREND_CHART_PADDING_X + (step * index);
            double normalized = maxCoverage <= 0.0d ? 0.0d : (point.overallCoveragePercent() / maxCoverage);
            double y = TREND_CHART_HEIGHT - TREND_CHART_PADDING_Y - (normalized * (TREND_CHART_HEIGHT - (TREND_CHART_PADDING_Y * 2)));
            chartPoints.add(new PublicBenchmarkSiteView.TrendChartPoint(
                    point.benchmarkVersion(),
                    point.generatedAt() != null ? point.generatedAt().toString() : "-",
                    point.overallCoveragePercent(),
                    x,
                    y,
                    point.passingOfficialMetricCount(),
                    point.failingOfficialMetricCount()));
        }
        String polyline = chartPoints.stream()
                .map(point -> String.format(Locale.US, "%.2f,%.2f", point.x(), point.y()))
                .collect(Collectors.joining(" "));
        return new PublicBenchmarkSiteView.TrendChartView(TREND_CHART_WIDTH, TREND_CHART_HEIGHT, maxCoverage, polyline, chartPoints);
    }
    private PublicBenchmarkSiteView.TrendChartView emptyTrendChart() {
        return new PublicBenchmarkSiteView.TrendChartView(TREND_CHART_WIDTH, TREND_CHART_HEIGHT, 100.0d, "", List.of());
    }

    private List<PublicBenchmarkSiteView.HeatmapCell> buildHeatmapCells(PublishedBenchmarkSummary report) {
        return safeScenarioRows(report).stream()
                .map(row -> {
                    double denominator = Math.max(Math.abs(row.expected()), 1.0d);
                    double deltaPercent = ((row.actual() - row.expected()) / denominator) * 100.0d;
                    double intensity = Math.min(0.85d, 0.18d + (Math.abs(deltaPercent) / 100.0d));
                    String background = row.pass()
                            ? String.format(Locale.US, "rgba(6, 214, 160, %.3f)", intensity)
                            : String.format(Locale.US, "rgba(230, 57, 70, %.3f)", intensity);
                    return new PublicBenchmarkSiteView.HeatmapCell(
                            row.key(),
                            row.label(),
                            row.category(),
                            row.actual(),
                            row.expected(),
                            row.pass(),
                            deltaPercent,
                            background);
                })
                .toList();
    }

    private List<PublishedBenchmarkScenarioMatrix.Row> safeScenarioRows(PublishedBenchmarkSummary report) {
        if (report.scenarioMatrix() == null || report.scenarioMatrix().rows() == null) {
            return List.of();
        }
        return report.scenarioMatrix().rows();
    }

    private List<PublishedBenchmarkTrendView.Point> safeTrendPoints(PublishedBenchmarkSummary report) {
        if (report.trendView() == null || report.trendView().points() == null) {
            return List.of();
        }
        return report.trendView().points();
    }

    private List<String> safeStrings(List<String> values) {
        return values == null ? List.of() : values;
    }

    private List<BenchmarkClaimResult> safeClaims(PublishedBenchmarkSummary report) {
        return report.claims() == null ? List.of() : report.claims();
    }

    private List<BenchmarkFacetResult> safeFacets(PublishedBenchmarkSummary report) {
        return report.facets() == null ? List.of() : report.facets();
    }

    private List<io.contexa.contexacoreenterprise.benchmark.contract.PublishedBenchmarkMetricView> safeOfficialMetrics(PublishedBenchmarkSummary report) {
        return report.officialMetrics() == null ? List.of() : report.officialMetrics();
    }

    private List<io.contexa.contexacoreenterprise.benchmark.exploit.ExploitWindowControlCase> safeExploitCases(PublishedBenchmarkSummary report) {
        return report.exploitWindowCases() == null ? List.of() : report.exploitWindowCases();
    }

    private List<io.contexa.contexacoreenterprise.benchmark.exploit.ExploitWindowReductionClaim> safeExploitClaims(PublishedBenchmarkSummary report) {
        return report.exploitWindowClaims() == null ? List.of() : report.exploitWindowClaims();
    }

    private List<io.contexa.contexacoreenterprise.benchmark.contract.PublishedBenchmarkSuiteView> safeSuites(PublishedBenchmarkSummary report) {
        return report.suiteSummaries() == null ? List.of() : report.suiteSummaries();
    }
    private static final class ClaimLandscapeAccumulator {
        private final String title;
        private int publishedReportCount;
        private int passingReportCount;
        private double totalScore;
        private final java.util.LinkedHashSet<String> sourceFamilies = new java.util.LinkedHashSet<>();

        private ClaimLandscapeAccumulator(String title) {
            this.title = title;
        }
    }

    private String countOrState(int count, String emptyState) {
        return count > 0 ? Integer.toString(count) : emptyState;
    }
}
