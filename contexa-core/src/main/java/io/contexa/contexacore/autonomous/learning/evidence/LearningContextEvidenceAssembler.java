package io.contexa.contexacore.autonomous.learning.evidence;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class LearningContextEvidenceAssembler {

    public LearningContextEvidence assemble(
            String userId,
            SecurityEvent event,
            CanonicalSecurityContext canonicalSecurityContext,
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis,
            List<Document> relatedDocuments) {
        CurrentLearningContextSnapshot current = buildCurrentSnapshot(event, canonicalSecurityContext);
        BaselineEvidenceSnapshot personalBaseline = buildPersonalBaseline(behaviorAnalysis);
        BaselineEvidenceSnapshot supportingBaseline = buildSupportingBaseline(behaviorAnalysis);

        List<RetrievedBehaviorEvidence> personalEvidence = new ArrayList<>();
        List<RetrievedBehaviorEvidence> supportingEvidence = new ArrayList<>();
        for (Document document : relatedDocuments == null ? List.<Document>of() : relatedDocuments) {
            RetrievedBehaviorEvidence normalized = normalizeDocument(userId, document);
            if (normalized == null) {
                continue;
            }
            if (normalized.scope() == LearningEvidenceScope.PERSONAL) {
                personalEvidence.add(normalized);
            } else {
                supportingEvidence.add(normalized);
            }
        }
        personalEvidence.sort(this::compareEvidence);
        supportingEvidence.sort(this::compareEvidence);

        ObservedPatternSnapshot observed = buildObservedPatterns(personalBaseline, personalEvidence);
        List<CurrentVsObservedDeltaSnapshot> deltas = buildCurrentVsObservedDeltas(current, observed);
        List<String> carryRequiredFacts = buildCarryRequiredFacts(current);
        List<String> carryMissingFacts = buildCarryMissingFacts(current, observed, personalBaseline, personalEvidence);

        return assemble(
                current,
                personalBaseline,
                supportingBaseline,
                personalEvidence,
                supportingEvidence,
                observed,
                deltas,
                carryRequiredFacts,
                carryMissingFacts);
    }

    public LearningContextEvidence assemble(
            CurrentLearningContextSnapshot current,
            BaselineEvidenceSnapshot personalBaseline,
            BaselineEvidenceSnapshot supportingBaseline,
            List<RetrievedBehaviorEvidence> personalEvidence,
            List<RetrievedBehaviorEvidence> supportingEvidence) {
        ObservedPatternSnapshot observed = buildObservedPatterns(personalBaseline, personalEvidence);
        List<CurrentVsObservedDeltaSnapshot> deltas = buildCurrentVsObservedDeltas(current, observed);
        List<String> carryRequiredFacts = buildCarryRequiredFacts(current);
        List<String> carryMissingFacts = buildCarryMissingFacts(current, observed, personalBaseline, personalEvidence);
        return assemble(
                current,
                personalBaseline,
                supportingBaseline,
                personalEvidence,
                supportingEvidence,
                observed,
                deltas,
                carryRequiredFacts,
                carryMissingFacts);
    }

    public LearningContextEvidence assemble(
            CurrentLearningContextSnapshot current,
            BaselineEvidenceSnapshot personalBaseline,
            BaselineEvidenceSnapshot supportingBaseline,
            List<RetrievedBehaviorEvidence> personalEvidence,
            List<RetrievedBehaviorEvidence> supportingEvidence,
            ObservedPatternSnapshot observed,
            List<CurrentVsObservedDeltaSnapshot> deltas,
            List<String> carryRequiredFacts,
            List<String> carryMissingFacts) {
        return new LearningContextEvidence(
                current,
                personalBaseline,
                supportingBaseline,
                personalEvidence,
                supportingEvidence,
                observed,
                deltas,
                carryRequiredFacts,
                carryMissingFacts);
    }

    public RetrievedBehaviorEvidence normalizeRetrievedBehaviorEvidence(String userId, Document document) {
        return normalizeDocument(userId, document);
    }

    private CurrentLearningContextSnapshot buildCurrentSnapshot(
            SecurityEvent event,
            CanonicalSecurityContext canonicalSecurityContext) {
        CanonicalSecurityContext.Session session = canonicalSecurityContext != null ? canonicalSecurityContext.getSession() : null;
        CanonicalSecurityContext.Device device = canonicalSecurityContext != null ? canonicalSecurityContext.getDevice() : null;
        CanonicalSecurityContext.Resource resource = canonicalSecurityContext != null ? canonicalSecurityContext.getResource() : null;
        CanonicalSecurityContext.RoleScopeProfile roleScope = canonicalSecurityContext != null ? canonicalSecurityContext.getRoleScopeProfile() : null;
        return new CurrentLearningContextSnapshot(
                text(event != null && event.getTimestamp() != null
                        ? event.getTimestamp().getHour()
                        : session != null ? session.getCurrentAccessHour() : null),
                text(event != null && event.getTimestamp() != null ? event.getTimestamp().getDayOfWeek().getValue() : null),
                SecuritySemanticNormalizer.normalizeNetwork(
                        event != null ? event.getSourceIp() : null,
                        canonicalSecurityContext != null && canonicalSecurityContext.getLocation() != null
                                ? canonicalSecurityContext.getLocation().getIpBand()
                                : null),
                browser(device),
                text(device != null ? device.getOs() : null),
                SecuritySemanticNormalizer.normalizePathFamily(firstText(resource != null ? resource.getRequestPath() : null, extractRequestPath(event))),
                SecuritySemanticNormalizer.normalizeAuthenticationType(
                        session != null ? session.getAuthenticationType() : null,
                        event != null && event.getMetadata() != null ? event.getMetadata().get("authMethod") : null),
                SecuritySemanticNormalizer.normalizeActionFamily(
                        resource != null ? resource.getActionFamily() : null,
                        roleScope != null ? roleScope.getCurrentActionFamily() : null,
                        resource != null ? resource.getHttpMethod() : null),
                SecuritySemanticNormalizer.normalizeResourceFamily(
                        roleScope != null ? roleScope.getCurrentResourceFamily() : null,
                        resource != null ? resource.getResourceType() : null,
                        resource != null ? resource.getSensitivity() : null));
    }

    private BaselineEvidenceSnapshot buildPersonalBaseline(SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis) {
        if (behaviorAnalysis == null) {
            return new BaselineEvidenceSnapshot(
                    LearningEvidenceScope.PERSONAL,
                    false,
                    false,
                    null,
                    null,
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    "",
                    BaselineEvidenceStatus.ANALYSIS_UNAVAILABLE,
                    "behavior analysis unavailable");
        }
        if (behaviorAnalysis.getPersonalBaselineEvidence() != null) {
            return behaviorAnalysis.getPersonalBaselineEvidence();
        }
        List<String> networks = normalizeStrings(
                behaviorAnalysis.getBaselineIpRanges(),
                value -> SecuritySemanticNormalizer.normalizeNetwork(null, value));
        List<String> accessHours = integers(behaviorAnalysis.getBaselineAccessHours());
        List<String> accessDays = integers(behaviorAnalysis.getBaselineAccessDays());
        List<String> browsers = strings(firstNonEmpty(
                behaviorAnalysis.getBaselineBrowsers(),
                behaviorAnalysis.getBaselineUserAgents()));
        List<String> operatingSystems = strings(behaviorAnalysis.getBaselineOperatingSystems());
        List<String> pathFamilies = normalizeStrings(behaviorAnalysis.getBaselineFrequentPaths(), SecuritySemanticNormalizer::normalizePathFamily);
        List<String> authTypes = normalizeStrings(behaviorAnalysis.getBaselineAuthenticationTypes(), SecuritySemanticNormalizer::normalizeAuthenticationType);
        List<String> actionFamilies = normalizeStrings(behaviorAnalysis.getBaselineActionFamilies(), SecuritySemanticNormalizer::normalizeActionFamily);
        List<String> resourceFamilies = normalizeStrings(behaviorAnalysis.getBaselineResourceFamilies(), SecuritySemanticNormalizer::normalizeResourceFamily);
        BaselineEvidenceStatus status = derivePersonalBaselineStatus(behaviorAnalysis);
        String summary = buildBaselineSummary(
                behaviorAnalysis.isPersonalBaselineEstablished(),
                behaviorAnalysis.getBaselineUpdateCount(),
                accessHours,
                accessDays,
                browsers,
                pathFamilies,
                authTypes,
                actionFamilies,
                resourceFamilies);
        return new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL,
                behaviorAnalysis.isPersonalBaselineAvailable(),
                behaviorAnalysis.isPersonalBaselineEstablished(),
                behaviorAnalysis.getBaselineUpdateCount(),
                behaviorAnalysis.getBaselineAvgTrustScore(),
                networks,
                accessHours,
                accessDays,
                browsers,
                operatingSystems,
                pathFamilies,
                authTypes,
                actionFamilies,
                resourceFamilies,
                summary,
                status,
                "");
    }

    private BaselineEvidenceSnapshot buildSupportingBaseline(SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis) {
        if (behaviorAnalysis == null) {
            return new BaselineEvidenceSnapshot(
                    LearningEvidenceScope.SUPPORTING,
                    false,
                    false,
                    null,
                    null,
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    "",
                    BaselineEvidenceStatus.ANALYSIS_UNAVAILABLE,
                    "behavior analysis unavailable");
        }
        if (behaviorAnalysis.getSupportingBaselineEvidence() != null) {
            return behaviorAnalysis.getSupportingBaselineEvidence();
        }
        List<String> policyFacts = behaviorAnalysis.getCohortSeedPolicyFacts() == null
                ? List.of()
                : behaviorAnalysis.getCohortSeedPolicyFacts().stream()
                .filter(StringUtils::hasText)
                .limit(4)
                .toList();
        StringBuilder summary = new StringBuilder();
        if (behaviorAnalysis.isOrganizationBaselineAvailable()) {
            summary.append("organization baseline available");
        }
        if (behaviorAnalysis.isOrganizationBaselineEstablished()) {
            appendSummary(summary, "organization baseline established");
        }
        if (behaviorAnalysis.getCohortBaselineSeed() != null && StringUtils.hasText(behaviorAnalysis.getCohortBaselineSeed().cohortLabel())) {
            appendSummary(summary, "cohort=" + behaviorAnalysis.getCohortBaselineSeed().cohortLabel());
        }
        if (!policyFacts.isEmpty()) {
            appendSummary(summary, "policyFacts=" + String.join(", ", policyFacts));
        }
        return new BaselineEvidenceSnapshot(
                LearningEvidenceScope.SUPPORTING,
                behaviorAnalysis.isOrganizationBaselineAvailable()
                        || behaviorAnalysis.getCohortBaselineSeed() != null,
                behaviorAnalysis.isOrganizationBaselineEstablished(),
                null,
                null,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                summary.toString(),
                behaviorAnalysis.isOrganizationBaselineAvailable() || behaviorAnalysis.getCohortBaselineSeed() != null
                        ? BaselineEvidenceStatus.AVAILABLE
                        : BaselineEvidenceStatus.NO_DATA,
                "");
    }

    private ObservedPatternSnapshot buildObservedPatterns(
            BaselineEvidenceSnapshot personalBaseline,
            List<RetrievedBehaviorEvidence> personalEvidence) {
        Set<String> networks = new LinkedHashSet<>(personalBaseline.networks());
        Set<String> accessHours = new LinkedHashSet<>(personalBaseline.accessHours());
        Set<String> accessDays = new LinkedHashSet<>(personalBaseline.accessDays());
        Set<String> browsers = new LinkedHashSet<>(personalBaseline.browsers());
        Set<String> operatingSystems = new LinkedHashSet<>(personalBaseline.operatingSystems());
        Set<String> pathFamilies = new LinkedHashSet<>(personalBaseline.pathFamilies());
        Set<String> authenticationTypes = new LinkedHashSet<>(personalBaseline.authenticationTypes());
        Set<String> actionFamilies = new LinkedHashSet<>(personalBaseline.actionFamilies());
        Set<String> resourceFamilies = new LinkedHashSet<>(personalBaseline.resourceFamilies());

        for (RetrievedBehaviorEvidence evidence : personalEvidence) {
            addIfText(networks, SecuritySemanticNormalizer.normalizeNetwork(evidence.sourceIp(), evidence.ipBand()));
            addIfText(accessHours, evidence.accessHour());
            addIfText(accessDays, evidence.accessDay());
            addIfText(browsers, evidence.browser());
            addIfText(operatingSystems, evidence.operatingSystem());
            addIfText(pathFamilies, SecuritySemanticNormalizer.normalizePathFamily(evidence.pathFamily()));
            addIfText(authenticationTypes, SecuritySemanticNormalizer.normalizeAuthenticationType(evidence.authenticationType()));
            addIfText(actionFamilies, SecuritySemanticNormalizer.normalizeActionFamily(evidence.actionFamily()));
            addIfText(resourceFamilies, SecuritySemanticNormalizer.normalizeResourceFamily(evidence.resourceFamily(), evidence.resourceSensitivity()));
        }
        return new ObservedPatternSnapshot(
                immutable(networks),
                immutable(accessHours),
                immutable(accessDays),
                immutable(browsers),
                immutable(operatingSystems),
                immutable(pathFamilies),
                immutable(authenticationTypes),
                immutable(actionFamilies),
                immutable(resourceFamilies));
    }

    private List<CurrentVsObservedDeltaSnapshot> buildCurrentVsObservedDeltas(
            CurrentLearningContextSnapshot current,
            ObservedPatternSnapshot observed) {
        List<CurrentVsObservedDeltaSnapshot> deltas = new ArrayList<>();
        addDelta(deltas, "accessHour", current.accessHour(), observed.accessHours(), "access hour outside observed hours");
        addDelta(deltas, "dayOfWeek", current.dayOfWeek(), observed.accessDays(), "day-of-week outside observed days");
        addDelta(deltas, "network", current.network(), observed.networks(), "network outside observed networks");
        addDelta(deltas, "browser", current.browser(), observed.browsers(), "browser outside observed browsers");
        addDelta(deltas, "operatingSystem", current.operatingSystem(), observed.operatingSystems(), "operating system outside observed operating systems");
        addDelta(deltas, "pathFamily", current.pathFamily(), observed.pathFamilies(), "path family unseen in observed paths");
        addDelta(deltas, "authenticationType", current.authenticationType(), observed.authenticationTypes(), "authentication type outside observed authentication types");
        addDelta(deltas, "actionFamily", current.actionFamily(), observed.actionFamilies(), "action family unseen in observed actions");
        addDelta(deltas, "resourceFamily", current.resourceFamily(), observed.resourceFamilies(), "resource family unseen in observed resources");
        return deltas;
    }

    private List<String> buildCarryRequiredFacts(CurrentLearningContextSnapshot current) {
        List<String> facts = new ArrayList<>(List.of(
                "WorkProfileEvidenceState",
                "ObservedPatternEvidenceScope",
                "HistoricalComparableScope",
                "CurrentVsObservedDeltaCount",
                "StrongestCurrentVsObservedDelta",
                "CurrentVsObservedDeltaSummary",
                "HistoricalComparableCount",
                "HistoricalComparableSummary",
                "ComparableExample1"));
        if (hasAnyCombinationSignal(current)) {
            facts.add("CurrentRequestCombinationEvidenceScope");
            facts.add("CurrentRequestCombinationSeenCount");
            facts.add("CurrentRequestCombinationComparedDimensions");
            facts.add("CurrentRequestClosestObservedOverlap");
            facts.add("StrongestCurrentRequestCombinationDelta");
            facts.add("CurrentRequestCombinationSummary");
            facts.add("ObservedComparableCombination1");
        }
        if (StringUtils.hasText(current.accessHour())) {
            facts.add("CurrentAccessHour");
            facts.add("CurrentAccessHourPresentInObservedHours");
        }
        if (StringUtils.hasText(current.dayOfWeek())) {
            facts.add("CurrentDayOfWeek");
            facts.add("CurrentDayPresentInObservedDays");
        }
        if (StringUtils.hasText(current.network())) {
            facts.add("CurrentNetwork");
            facts.add("CurrentNetworkPresentInObservedNetworks");
        }
        if (StringUtils.hasText(current.browser())) {
            facts.add("CurrentBrowser");
            facts.add("CurrentBrowserPresentInObservedBrowsers");
        }
        if (StringUtils.hasText(current.operatingSystem())) {
            facts.add("CurrentOperatingSystem");
            facts.add("CurrentOperatingSystemPresentInObservedOperatingSystems");
        }
        if (StringUtils.hasText(current.pathFamily())) {
            facts.add("CurrentPathFamily");
            facts.add("CurrentPathPresentInObservedPaths");
        }
        if (StringUtils.hasText(current.authenticationType())) {
            facts.add("CurrentAuthenticationType");
            facts.add("CurrentAuthenticationTypePresentInObservedAuthTypes");
        }
        if (StringUtils.hasText(current.actionFamily())) {
            facts.add("CurrentActionFamily");
            facts.add("CurrentActionFamilyPresentInObservedActions");
        }
        if (StringUtils.hasText(current.resourceFamily())) {
            facts.add("CurrentResourceFamily");
            facts.add("CurrentResourceFamilyPresentInObservedResources");
        }
        return List.copyOf(facts);
    }

    private List<String> buildCarryMissingFacts(
            CurrentLearningContextSnapshot current,
            ObservedPatternSnapshot observed,
            BaselineEvidenceSnapshot personalBaseline,
            List<RetrievedBehaviorEvidence> personalEvidence) {
        List<String> missing = new ArrayList<>();
        if (StringUtils.hasText(current.accessHour()) && observed.accessHours().isEmpty()) {
            missing.add("ObservedHours");
        }
        if (StringUtils.hasText(current.dayOfWeek()) && observed.accessDays().isEmpty()) {
            missing.add("ObservedDays");
        }
        if (StringUtils.hasText(current.network()) && observed.networks().isEmpty()) {
            missing.add("ObservedNetworks");
        }
        if (StringUtils.hasText(current.browser()) && observed.browsers().isEmpty()) {
            missing.add("ObservedBrowsers");
        }
        if (StringUtils.hasText(current.operatingSystem()) && observed.operatingSystems().isEmpty()) {
            missing.add("ObservedOperatingSystems");
        }
        if (StringUtils.hasText(current.pathFamily()) && observed.pathFamilies().isEmpty()) {
            missing.add("ObservedPaths");
        }
        if (StringUtils.hasText(current.authenticationType()) && observed.authenticationTypes().isEmpty()) {
            missing.add("ObservedAuthenticationTypes");
        }
        if (StringUtils.hasText(current.actionFamily()) && observed.actionFamilies().isEmpty()) {
            missing.add("ObservedActionFamilies");
        }
        if (StringUtils.hasText(current.resourceFamily()) && observed.resourceFamilies().isEmpty()) {
            missing.add("ObservedResourceFamilies");
        }
        if (!personalBaseline.available() && personalEvidence.isEmpty()) {
            missing.add("PersonalLearningEvidence");
        }
        return List.copyOf(missing);
    }

    private RetrievedBehaviorEvidence normalizeDocument(String userId, Document document) {
        if (document == null || document.getMetadata() == null) {
            return null;
        }
        Map<String, Object> metadata = document.getMetadata();
        String documentType = firstText(metadata.get("documentType"), metadata.get("sourceType"));
        if (StringUtils.hasText(documentType) && !"behavior".equalsIgnoreCase(documentType)) {
            return null;
        }
        String sourceUserId = text(metadata.get("userId"));
        LearningEvidenceScope scope = StringUtils.hasText(userId) && userId.equals(sourceUserId)
                ? LearningEvidenceScope.PERSONAL
                : LearningEvidenceScope.SUPPORTING;
        String documentPath = firstText(
                metadata.get("requestPath"),
                metadata.get("requestedResourceId"),
                metadata.get("protectedResourceId"),
                metadata.get("resourceId"),
                metadata.get("fullPath"));
        return new RetrievedBehaviorEvidence(
                scope,
                sourceUserId,
                documentType,
                firstText(metadata.get("artifactId"), metadata.get("eventId")),
                similarityScore(document),
                firstText(metadata.get("sourceIp")),
                SecuritySemanticNormalizer.normalizeNetwork(firstText(metadata.get("sourceIp")), firstText(metadata.get("ipBand"))),
                documentPath,
                SecuritySemanticNormalizer.normalizePathFamily(firstText(metadata.get("pathFamily"), documentPath, metadata.get("fullPath"))),
                text(metadata.get("hour")),
                text(metadata.get("dayOfWeek")),
                firstText(metadata.get("userAgentBrowser"), metadata.get("deviceBrowser")),
                firstText(metadata.get("userAgentOS"), metadata.get("deviceOs")),
                SecuritySemanticNormalizer.normalizeAuthenticationType(firstText(metadata.get("authenticationType"), metadata.get("authMethod"))),
                SecuritySemanticNormalizer.normalizeActionFamily(firstText(metadata.get("actionFamily"), metadata.get("httpMethod"), metadata.get("action"))),
                SecuritySemanticNormalizer.normalizeResourceFamily(firstText(metadata.get("resourceFamily"), metadata.get("resourceType"), metadata.get("resourceCategory"), metadata.get("resourceSensitivity"))),
                SecuritySemanticNormalizer.normalizeSensitivity(metadata.get("resourceSensitivity"), metadata.get("sensitivity")),
                firstText(metadata.get("resourceBusinessLabel"), metadata.get("businessLabel")),
                text(metadata.get("sessionAgeMinutes")),
                text(metadata.get("intentBotUserAgent")),
                summarizeDocument(document.getText()));
    }

    private String buildBaselineSummary(
            boolean established,
            Long updateCount,
            List<String> accessHours,
            List<String> accessDays,
            List<String> browsers,
            List<String> pathFamilies,
            List<String> authTypes,
            List<String> actionFamilies,
            List<String> resourceFamilies) {
        boolean hasObservedFacts = !accessHours.isEmpty()
                || !accessDays.isEmpty()
                || !browsers.isEmpty()
                || !pathFamilies.isEmpty()
                || !authTypes.isEmpty()
                || !actionFamilies.isEmpty()
                || !resourceFamilies.isEmpty();
        if (!established && updateCount == null && !hasObservedFacts) {
            return "";
        }
        List<String> parts = new ArrayList<>();
        parts.add(established ? "personal baseline established" : "personal baseline provisional");
        if (updateCount != null) {
            parts.add("observations=" + updateCount);
        }
        addSummary(parts, "hours", accessHours);
        addSummary(parts, "days", accessDays);
        addSummary(parts, "browsers", browsers);
        addSummary(parts, "paths", pathFamilies);
        addSummary(parts, "auth", authTypes);
        addSummary(parts, "actions", actionFamilies);
        addSummary(parts, "resources", resourceFamilies);
        return String.join(" | ", parts);
    }

    private BaselineEvidenceStatus derivePersonalBaselineStatus(
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis) {
        boolean hasObservedBaselineFacts = !strings(behaviorAnalysis.getBaselineIpRanges()).isEmpty()
                || !integers(behaviorAnalysis.getBaselineAccessHours()).isEmpty()
                || !integers(behaviorAnalysis.getBaselineAccessDays()).isEmpty()
                || !strings(firstNonEmpty(
                        behaviorAnalysis.getBaselineBrowsers(),
                        behaviorAnalysis.getBaselineUserAgents())).isEmpty()
                || !strings(behaviorAnalysis.getBaselineOperatingSystems()).isEmpty()
                || !strings(behaviorAnalysis.getBaselineFrequentPaths()).isEmpty()
                || !strings(behaviorAnalysis.getBaselineAuthenticationTypes()).isEmpty()
                || !strings(behaviorAnalysis.getBaselineActionFamilies()).isEmpty()
                || !strings(behaviorAnalysis.getBaselineResourceFamilies()).isEmpty();
        if (behaviorAnalysis.isPersonalBaselineAvailable()
                || behaviorAnalysis.isPersonalBaselineEstablished()
                || behaviorAnalysis.isBaselineEstablished()
                || (behaviorAnalysis.getBaselineUpdateCount() != null && hasObservedBaselineFacts)) {
            return BaselineEvidenceStatus.AVAILABLE;
        }
        return BaselineEvidenceStatus.NO_DATA;
    }

    private void addSummary(List<String> parts, String label, List<String> values) {
        if (!values.isEmpty()) {
            parts.add(label + "=" + String.join(", ", values.stream().limit(4).toList()));
        }
    }

    private void appendSummary(StringBuilder summary, String value) {
        if (!StringUtils.hasText(value)) {
            return;
        }
        if (summary.length() > 0) {
            summary.append(" | ");
        }
        summary.append(value);
    }

    private void addDelta(
            List<CurrentVsObservedDeltaSnapshot> deltas,
            String key,
            String currentValue,
            List<String> observedValues,
            String description) {
        if (!StringUtils.hasText(currentValue)) {
            return;
        }
        if (observedValues == null || observedValues.isEmpty()) {
            return;
        }
        boolean observed = containsIgnoreCase(observedValues, currentValue);
        if (observed) {
            return;
        }
        deltas.add(new CurrentVsObservedDeltaSnapshot(
                key,
                currentValue,
                summarizeObserved(observedValues),
                false,
                description,
                LearningEvidenceScope.PERSONAL));
    }

    private int compareEvidence(RetrievedBehaviorEvidence left, RetrievedBehaviorEvidence right) {
        return Double.compare(score(right), score(left));
    }

    private double score(RetrievedBehaviorEvidence evidence) {
        return evidence != null && evidence.similarityScore() != null ? evidence.similarityScore() : 0.0d;
    }

    private Double similarityScore(Document document) {
        try {
            Double direct = document.getScore();
            if (direct != null) {
                return direct;
            }
        } catch (Throwable ignored) {
            // Ignore provider-specific document score failures.
        }
        Map<String, Object> metadata = document.getMetadata();
        Object score = metadata.get("score");
        if (score instanceof Number number) {
            return number.doubleValue();
        }
        Object distance = metadata.get("distance");
        if (distance instanceof Number number) {
            return 1.0d - number.doubleValue();
        }
        return null;
    }

    private String summarizeDocument(String text) {
        if (!StringUtils.hasText(text)) {
            return null;
        }
        return text.length() > 180 ? text.substring(0, 180) + "..." : text;
    }

    private String summarizeObserved(List<String> values) {
        if (values == null || values.isEmpty()) {
            return "none";
        }
        return values.stream().limit(6).collect(Collectors.joining(", "));
    }

    private boolean containsIgnoreCase(List<String> values, String currentValue) {
        if (!StringUtils.hasText(currentValue) || values == null || values.isEmpty()) {
            return false;
        }
        return values.stream()
                .filter(StringUtils::hasText)
                .anyMatch(value -> value.equalsIgnoreCase(currentValue));
    }

    private String browser(CanonicalSecurityContext.Device device) {
        if (device == null || !StringUtils.hasText(device.getBrowser())) {
            return null;
        }
        if (StringUtils.hasText(device.getBrowserVersion())) {
            return device.getBrowser() + "/" + device.getBrowserVersion();
        }
        return device.getBrowser();
    }

    private String extractRequestPath(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return null;
        }
        return firstText(event.getMetadata().get("requestPath"), event.getMetadata().get("requestUri"));
    }

    private String[] firstNonEmpty(String[] primary, String[] fallback) {
        return primary != null && primary.length > 0 ? primary : fallback;
    }

    private List<String> strings(String[] values) {
        if (values == null || values.length == 0) {
            return List.of();
        }
        return Arrays.stream(values)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private List<String> normalizeStrings(String[] values, java.util.function.Function<String, String> normalizer) {
        if (values == null || values.length == 0 || normalizer == null) {
            return List.of();
        }
        return Arrays.stream(values)
                .filter(StringUtils::hasText)
                .map(normalizer)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private List<String> integers(Integer[] values) {
        if (values == null || values.length == 0) {
            return List.of();
        }
        return Arrays.stream(values)
                .filter(Objects::nonNull)
                .map(String::valueOf)
                .distinct()
                .toList();
    }

    private List<String> immutable(Set<String> values) {
        return values.stream()
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private void addIfText(Set<String> target, String value) {
        if (StringUtils.hasText(value)) {
            target.add(value);
        }
    }

    private boolean hasAnyCombinationSignal(CurrentLearningContextSnapshot current) {
        if (current == null) {
            return false;
        }
        return StringUtils.hasText(current.accessHour())
                || StringUtils.hasText(current.authenticationType())
                || StringUtils.hasText(current.browser())
                || StringUtils.hasText(current.resourceFamily())
                || StringUtils.hasText(current.pathFamily());
    }

    private String firstText(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            String text = text(value);
            if (StringUtils.hasText(text)) {
                return text;
            }
        }
        return null;
    }

    private String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
    }
}
