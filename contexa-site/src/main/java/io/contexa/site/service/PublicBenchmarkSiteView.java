package io.contexa.site.service;

import io.contexa.contexacoreenterprise.benchmark.publication.BenchmarkPublicationStatus;

import java.time.Instant;
import java.util.List;

public final class PublicBenchmarkSiteView {

    private PublicBenchmarkSiteView() {
    }

    public record MethodologySection(String key, String title, String summary, List<String> principles) {
    }

    public record FamilyCard(String slug, String title, String summary, int publishedCount, int submissionReadyCount) {
    }

    public record SummaryCard(String label,
                              String value,
                              String caption,
                              String tone) {
    }

    public record CatalogHero(String slug,
                              String title,
                              String benchmarkVersion,
                              String sourceType,
                              String dossierUrl,
                              String kicker,
                              String statusLabel,
                              String statusTone,
                              double coveragePercent,
                              int passingOfficialMetricCount,
                              int officialMetricCount,
                              int claimCount,
                              int suiteCount,
                              String publishedLabel) {
    }

    public record CatalogStatusItem(String key,
                                    String label,
                                    String value,
                                    String tone,
                                    String note) {
    }

    public record CatalogOption(String value,
                                String label) {
    }

    public record CatalogFilterMetadata(List<CatalogOption> families,
                                        List<CatalogOption> statuses,
                                        List<CatalogOption> sourceTypes,
                                        List<CatalogOption> sortOptions) {
    }

    public record CatalogReportRow(String slug,
                                   String title,
                                   String benchmarkVersion,
                                   String sourceType,
                                   String familyLabel,
                                   String dossierUrl,
                                   double coveragePercent,
                                   int passingOfficialMetricCount,
                                   int officialMetricCount,
                                   int claimCount,
                                   int suiteCount,
                                   boolean submissionReady,
                                   BenchmarkPublicationStatus status,
                                   String publishedLabel) {
    }

    public record CertificationSnapshotRow(String key,
                                           String title,
                                           boolean ready,
                                           int matchingReportCount,
                                           String latestMappedReport,
                                           String readinessBasis,
                                           String tone,
                                           List<String> requiredSignals) {
    }

    public record MethodologyAlignmentRow(String key,
                                          String title,
                                          String summary,
                                          String relevance) {
    }

    public record CertificationProfileMatrixRow(String key,
                                                String title,
                                                boolean ready,
                                                int matchingReportCount,
                                                String latestMappedReport,
                                                String tone,
                                                List<String> requiredSignals) {
    }

    public record CertificationEvidenceRow(String profileKey,
                                           String profileTitle,
                                           List<String> requiredSignals,
                                           List<String> matchingSlugs,
                                           List<String> mappedClaimKeys,
                                           List<String> mappedSuiteKeys,
                                           String readinessBasis,
                                           String evidenceStatusDetails,
                                           String profileNote) {
    }
    public record SpotlightReport(String slug,
                                  String title,
                                  String benchmarkVersion,
                                  String sourceType,
                                  double coveragePercent,
                                  int passingOfficialMetricCount,
                                  int officialMetricCount,
                                  int failingGateCount,
                                  boolean submissionReady,
                                  int verifiedCaseCount,
                                  int evaluationCaseCount,
                                  int claimCount,
                                  int suiteCount,
                                  int facetCount) {
    }

    public record FacetRouteCard(String slug,
                                 String title,
                                 String summary,
                                 boolean current,
                                 String publishedLabel,
                                 String submissionReadyLabel) {
    }

    public record TrendRow(String slug,
                           String sourceLabel,
                           String title,
                           String benchmarkVersion,
                           Instant generatedAt,
                           double coveragePercent,
                           int passingOfficialMetricCount,
                           int officialMetricCount,
                           BenchmarkPublicationStatus status) {
    }

    public record LeaderboardRow(int rank,
                                 String sourceLabel,
                                 String slug,
                                 String title,
                                 String benchmarkVersion,
                                 double coveragePercent,
                                 int passingOfficialMetricCount,
                                 int officialMetricCount,
                                 boolean submissionReady,
                                 BenchmarkPublicationStatus status) {
    }

    public record ReportDonutView(String cssGradient,
                                  int totalCount,
                                  List<DonutLegendItem> segments) {
    }

    public record DonutLegendItem(String label,
                                  int value,
                                  String tone,
                                  String color) {
    }

    public record TrendChartView(double width,
                                 double height,
                                 double maxCoverage,
                                 String polyline,
                                 List<TrendChartPoint> points) {
    }

    public record TrendChartPoint(String label,
                                  String generatedLabel,
                                  double coveragePercent,
                                  double x,
                                  double y,
                                  int passingOfficialMetricCount,
                                  int failingOfficialMetricCount) {
    }

    public record HeatmapCell(String key,
                              String label,
                              String category,
                              double actual,
                              double expected,
                              boolean pass,
                              double deltaPercent,
                              String background) {
    }

    public record DossierHero(String slug,
                              String title,
                              String benchmarkVersion,
                              String sourceType,
                              String statusLabel,
                              String statusTone,
                              String dossierNote,
                              boolean submissionReady,
                              double coveragePercent,
                              int claimCount,
                              int suiteCount,
                              String publishedLabel) {
    }

    public record DossierProvenanceStrip(int sourceVerifiedCaseCount,
                                         int sourceEvaluationCaseCount,
                                         int verifiedMetricCount,
                                         double replayCoverageRate,
                                         double assuranceCoverageRate,
                                         String methodologyVersion,
                                         String sanitizationProfileVersion,
                                         String suiteVersion,
                                         String lastVerifiedLabel) {
    }

    public record DossierOfficialGateSummary(int officialMetricCount,
                                             int passingOfficialMetricCount,
                                             int failingOfficialMetricCount,
                                             List<String> missingOfficialMetrics,
                                             boolean submissionReady) {
    }

    public record DossierExploitWindowSummary(boolean present,
                                              int claimCount,
                                              int caseCount,
                                              long averageLatencyMillis,
                                              long maxLatencyMillis,
                                              double controlCoverageRate,
                                              double permitContinuityRate) {
    }
    public record ReportExecutiveView(String statusLabel,
                                      String statusTone,
                                      String summary,
                                      String readerGuidance,
                                      List<ReportDocketItem> docketItems,
                                      List<ReportKpiCard> kpiCards) {
    }

    public record ReportDocketItem(String label,
                                   String value,
                                   String note) {
    }

    public record ReportKpiCard(String label,
                                String value,
                                String note,
                                String tone) {
    }

    public record ClaimHighlightCard(String key,
                                     String title,
                                     double score,
                                     boolean pass,
                                     String supportingSuites,
                                     int passingEvaluationCaseCount,
                                     int sourceEvaluationCaseCount) {
    }
    public record ClaimLandscapeRow(String key,
                                    String title,
                                    int publishedReportCount,
                                    int passingReportCount,
                                    double averageScore,
                                    String sourceFamilies) {
    }

    public record ReportClaimScoreRow(String key,
                                      String title,
                                      double score,
                                      boolean pass,
                                      String supportingSuites,
                                      int passingEvaluationCaseCount,
                                      int sourceEvaluationCaseCount,
                                      List<String> failingGates) {
    }

    public record ReportScenarioRow(String key,
                                    String label,
                                    String category,
                                    double actual,
                                    double expected,
                                    double deltaPercent,
                                    boolean pass,
                                    List<String> claimKeys,
                                    List<String> suiteKeys,
                                    String deviationClass) {
    }

    public record ReportTrendComparisonRow(String label,
                                           String versionMarker,
                                           String milestoneLabel,
                                           String sourceLabel,
                                           String generatedLabel,
                                           double coveragePercent,
                                           Double deltaFromPrevious,
                                           int passingOfficialMetricCount,
                                           int failingOfficialMetricCount) {
    }

    public record ReportArtifactCard(String title,
                                     String href,
                                     String summary,
                                     String identity) {
    }

    public record ReportConstraint(String title,
                                   String detail,
                                   String tone) {
    }
}
