package io.contexa.contexacore.autonomous.saas.threat;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceMatchContext;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackMatchContext;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackSnapshot;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

public class ThreatSignalMatcherService {

    private final ThreatSignalNormalizationService normalizationService;

    public ThreatSignalMatcherService() {
        this(new ThreatSignalNormalizationService());
    }

    public ThreatSignalMatcherService(ThreatSignalNormalizationService normalizationService) {
        this.normalizationService = normalizationService;
    }

    public ThreatIntelligenceMatchContext buildContext(
            SecurityEvent event,
            SecurityPromptTemplate.BehaviorAnalysis behaviorAnalysis,
            List<ThreatIntelligenceSnapshot.ThreatSignalItem> activeSignals,
            int limit) {
        if (event == null || activeSignals == null || activeSignals.isEmpty()) {
            return ThreatIntelligenceMatchContext.empty();
        }

        EventTraits traits = deriveTraits(event, behaviorAnalysis);
        List<ThreatIntelligenceMatchContext.MatchedSignal> matches = activeSignals.stream()
                .map(signal -> matchSignal(signal, traits))
                .filter(candidate -> candidate != null)
                .sorted(Comparator
                        .comparing(CandidateMatch::matchedFactCount, Comparator.reverseOrder())
                        .thenComparing(CandidateMatch::matchingDimensions, Comparator.reverseOrder())
                        .thenComparing(CandidateMatch::recentlyObserved, Comparator.reverseOrder())
                        .thenComparing(CandidateMatch::affectedTenantCount, Comparator.reverseOrder())
                        .thenComparing(CandidateMatch::observationCount, Comparator.reverseOrder())
                        .thenComparing(CandidateMatch::lastObservedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .limit(Math.max(1, limit))
                .map(CandidateMatch::match)
                .toList();
        if (matches.isEmpty()) {
            return ThreatIntelligenceMatchContext.empty();
        }

        return new ThreatIntelligenceMatchContext(true, matches);
    }

    public ThreatKnowledgePackMatchContext buildKnowledgeContext(
            SecurityEvent event,
            SecurityPromptTemplate.BehaviorAnalysis behaviorAnalysis,
            List<ThreatKnowledgePackSnapshot.KnowledgeCaseItem> knowledgeCases,
            int limit) {
        if (event == null || knowledgeCases == null || knowledgeCases.isEmpty()) {
            return ThreatKnowledgePackMatchContext.empty();
        }

        EventTraits traits = deriveTraits(event, behaviorAnalysis);
        List<ThreatKnowledgePackMatchContext.MatchedKnowledgeCase> matches = knowledgeCases.stream()
                .map(knowledgeCase -> matchKnowledgeCase(knowledgeCase, traits))
                .filter(candidate -> candidate != null)
                .sorted(Comparator
                        .comparing(KnowledgeCandidateMatch::matchedFactCount, Comparator.reverseOrder())
                        .thenComparing(KnowledgeCandidateMatch::matchingDimensions, Comparator.reverseOrder())
                        .thenComparing(KnowledgeCandidateMatch::recentlyObserved, Comparator.reverseOrder())
                        .thenComparing(KnowledgeCandidateMatch::affectedTenantCount, Comparator.reverseOrder())
                        .thenComparing(KnowledgeCandidateMatch::observationCount, Comparator.reverseOrder())
                        .thenComparing(KnowledgeCandidateMatch::lastObservedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .limit(Math.max(1, limit))
                .map(KnowledgeCandidateMatch::match)
                .toList();
        if (matches.isEmpty()) {
            return ThreatKnowledgePackMatchContext.empty();
        }

        return new ThreatKnowledgePackMatchContext(true, matches);
    }

    private CandidateMatch matchSignal(
            ThreatIntelligenceSnapshot.ThreatSignalItem signal,
            EventTraits traits) {
        if (signal == null) {
            return null;
        }

        MatchFacts facts = buildMatchFacts(
                signal.canonicalThreatClass(),
                signal.geoCountry(),
                signal.targetSurfaceHints(),
                signal.signalTags(),
                traits,
                false);
        if (!facts.concreteOverlap()) {
            return null;
        }

        List<String> distinctFacts = facts.facts().stream().distinct().toList();
        ThreatIntelligenceMatchContext.MatchedSignal match = new ThreatIntelligenceMatchContext.MatchedSignal(signal, distinctFacts);
        return new CandidateMatch(
                distinctFacts.size(),
                facts.matchingDimensions(),
                isRecentlyObserved(signal.lastObservedAt()),
                signal.affectedTenantCount(),
                signal.observationCount(),
                signal.lastObservedAt(),
                match);
    }

    private KnowledgeCandidateMatch matchKnowledgeCase(
            ThreatKnowledgePackSnapshot.KnowledgeCaseItem knowledgeCase,
            EventTraits traits) {
        if (knowledgeCase == null) {
            return null;
        }

        MatchFacts facts = buildMatchFacts(
                knowledgeCase.canonicalThreatClass(),
                knowledgeCase.geoCountry(),
                knowledgeCase.targetSurfaceHints(),
                knowledgeCase.signalTags(),
                traits,
                true);
        if (!facts.concreteOverlap()) {
            return null;
        }

        List<String> distinctFacts = facts.facts().stream().distinct().toList();
        ThreatKnowledgePackMatchContext.MatchedKnowledgeCase match =
                new ThreatKnowledgePackMatchContext.MatchedKnowledgeCase(knowledgeCase, distinctFacts);
        return new KnowledgeCandidateMatch(
                distinctFacts.size(),
                facts.matchingDimensions(),
                isRecentlyObserved(knowledgeCase.lastObservedAt()),
                knowledgeCase.affectedTenantCount(),
                knowledgeCase.observationCount(),
                knowledgeCase.lastObservedAt(),
                match);
    }

    private MatchFacts buildMatchFacts(
            String canonicalThreatClass,
            String geoCountry,
            List<String> targetSurfaceHints,
            List<String> signalTags,
            EventTraits traits,
            boolean caseMode) {
        List<String> matchedFacts = new ArrayList<>();
        int matchingDimensions = 0;
        boolean concreteOverlap = false;

        if (matchesGeo(geoCountry, traits)) {
            matchedFacts.add(geoFact(geoCountry, caseMode));
            matchingDimensions += 1;
        }
        if (matchesTargetSurface(targetSurfaceHints, traits)) {
            matchedFacts.add(surfaceFact(traits.pathCategory(), caseMode));
            matchingDimensions += 1;
            concreteOverlap = true;
        }

        List<String> tagFacts = matchedTagFacts(signalTags, traits, caseMode);
        if (!tagFacts.isEmpty()) {
            matchedFacts.addAll(tagFacts);
            matchingDimensions += 1;
            concreteOverlap = true;
        }

        if (appendThreatClassMatches(canonicalThreatClass, traits, matchedFacts, caseMode)) {
            matchingDimensions += 1;
            concreteOverlap = true;
        }
        if (traits.sensitiveResource()) {
            matchedFacts.add(caseMode
                    ? "The current request is touching a sensitive resource, so similar campaign cases deserve careful review."
                    : "The current request touches a sensitive resource.");
            matchingDimensions += 1;
        }
        return new MatchFacts(matchedFacts, matchingDimensions, concreteOverlap);
    }

    private EventTraits deriveTraits(SecurityEvent event, SecurityPromptTemplate.BehaviorAnalysis behaviorAnalysis) {
        Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        String requestPath = extractText(metadata, "requestPath");
        if (!StringUtils.hasText(requestPath)) {
            requestPath = extractText(metadata, "requestUri");
        }
        String geoCountry = normalize(extractText(metadata, "geoCountry"));
        boolean newDevice = extractBoolean(metadata, "isNewDevice")
                || (behaviorAnalysis != null && Boolean.TRUE.equals(behaviorAnalysis.getIsNewDevice()));
        boolean impossibleTravel = extractBoolean(metadata, "isImpossibleTravel");
        boolean sensitiveResource = extractBoolean(metadata, "isSensitiveResource");
        int failedLoginAttempts = extractInt(metadata, "failedLoginAttempts");
        if (failedLoginAttempts <= 0) {
            failedLoginAttempts = extractInt(metadata, "auth.failure_count");
        }
        String pathCategory = normalizationService.classifyTargetSurface(requestPath);
        boolean browserChanged = behaviorAnalysis != null
                && StringUtils.hasText(behaviorAnalysis.getPreviousUserAgentBrowser())
                && StringUtils.hasText(behaviorAnalysis.getCurrentUserAgentBrowser())
                && !behaviorAnalysis.getPreviousUserAgentBrowser().equalsIgnoreCase(behaviorAnalysis.getCurrentUserAgentBrowser());
        boolean osChanged = behaviorAnalysis != null
                && StringUtils.hasText(behaviorAnalysis.getPreviousUserAgentOS())
                && StringUtils.hasText(behaviorAnalysis.getCurrentUserAgentOS())
                && !behaviorAnalysis.getPreviousUserAgentOS().equalsIgnoreCase(behaviorAnalysis.getCurrentUserAgentOS());
        boolean sessionAnomaly = behaviorAnalysis != null && Boolean.TRUE.equals(behaviorAnalysis.getContextBindingHashMismatch());
        Set<String> tags = new LinkedHashSet<>();
        if (StringUtils.hasText(pathCategory)) {
            tags.add("surface_" + normalize(pathCategory));
        }
        if (newDevice) {
            tags.add("new_device");
        }
        if (impossibleTravel) {
            tags.add("impossible_travel");
            tags.add("geo_velocity");
        }
        if (sensitiveResource) {
            tags.add("sensitive_resource");
        }
        if (failedLoginAttempts >= 3) {
            tags.add("failed_login_burst");
        }
        if (sessionAnomaly) {
            tags.add("session_integrity_risk");
        }
        if (browserChanged || osChanged) {
            tags.add("device_reputation_shift");
        }
        String userRoles = normalize(extractText(metadata, "userRoles"));
        if (containsText(userRoles, "admin", "privilege", "operator")) {
            tags.add("privileged_flow");
        }
        return new EventTraits(
                requestPath,
                pathCategory,
                geoCountry,
                newDevice,
                impossibleTravel,
                sensitiveResource,
                failedLoginAttempts,
                browserChanged,
                osChanged,
                sessionAnomaly,
                Set.copyOf(tags));
    }

    private boolean appendThreatClassMatches(String canonicalThreatClass, EventTraits traits, List<String> matchedFacts, boolean caseMode) {
        if (!StringUtils.hasText(canonicalThreatClass)) {
            return false;
        }
        return switch (canonicalThreatClass) {
            case "account_takeover" -> {
                boolean matched = false;
                if ("authentication".equals(traits.pathCategory()) || traits.failedLoginAttempts() >= 3) {
                    matchedFacts.add(caseMode
                            ? "This request is in an authentication flow that resembles past account takeover cases."
                            : "The request is part of an authentication flow that resembles account takeover behavior.");
                    matched = true;
                }
                if (traits.newDevice() || traits.impossibleTravel()) {
                    matchedFacts.add(caseMode
                            ? "This request also carries new-device or impossible-travel context seen in past account takeover outcomes."
                            : "The request also shows new-device or impossible-travel context that is commonly present in account takeover campaigns.");
                    matched = true;
                }
                yield matched;
            }
            case "credential_abuse" -> {
                if ("authentication".equals(traits.pathCategory()) || traits.failedLoginAttempts() >= 3) {
                    matchedFacts.add(caseMode
                            ? "This request shares authentication and repeated-failure traits with credential abuse cases."
                            : "The request is on the authentication surface with repeated login failures, which matches credential abuse campaigns.");
                    yield true;
                }
                yield false;
            }
            case "session_hijack" -> {
                boolean matched = false;
                if (traits.sessionAnomaly()) {
                    matchedFacts.add(caseMode
                            ? "This request shows a session binding anomaly that aligns with past session hijack outcomes."
                            : "The current session shows a binding anomaly that is consistent with session hijacking attempts.");
                    matched = true;
                }
                if ("session".equals(traits.pathCategory())) {
                    matchedFacts.add(caseMode
                            ? "This request is targeting the session surface affected in past session hijack cases."
                            : "The request is targeting the session surface that this campaign is affecting.");
                    matched = true;
                }
                yield matched;
            }
            case "privilege_abuse" -> {
                boolean matched = false;
                if ("administration".equals(traits.pathCategory())) {
                    matchedFacts.add(caseMode
                            ? "This request is on an administrative surface that appears in past privilege abuse cases."
                            : "The request is on an administrative surface that has been affected by this campaign.");
                    matched = true;
                }
                if (traits.tags().contains("privileged_flow")) {
                    matchedFacts.add(caseMode
                            ? "This request is part of a privileged flow that aligns with prior privilege abuse outcomes."
                            : "The request is part of a privileged flow that aligns with privilege abuse activity.");
                    matched = true;
                }
                yield matched;
            }
            case "impossible_travel" -> {
                if (traits.impossibleTravel()) {
                    matchedFacts.add(caseMode
                            ? "This request carries impossible-travel context that mirrors prior reviewed cases."
                            : "The request carries impossible-travel context that matches the active campaign.");
                    yield true;
                }
                yield false;
            }
            case "suspicious_device_change" -> {
                if (traits.newDevice() || traits.browserChanged() || traits.osChanged()) {
                    matchedFacts.add(caseMode
                            ? "This request shows a device or browser change pattern that appears in prior reviewed cases."
                            : "The request shows a device or browser change pattern that matches the active campaign.");
                    yield true;
                }
                yield false;
            }
            case "anomalous_access" -> {
                if (traits.sensitiveResource() || StringUtils.hasText(traits.requestPath())) {
                    matchedFacts.add(caseMode
                            ? "This request has anomalous access context that resembles previous reviewed cases."
                            : "The request has anomalous access context that aligns with the active campaign.");
                    yield true;
                }
                yield false;
            }
            default -> false;
        };
    }

    private boolean matchesGeo(String signalGeoCountry, EventTraits traits) {
        if (!StringUtils.hasText(signalGeoCountry)) {
            return false;
        }
        if (!StringUtils.hasText(traits.geoCountry())) {
            return "GLOBAL".equalsIgnoreCase(signalGeoCountry);
        }
        return signalGeoCountry.equalsIgnoreCase(traits.geoCountry())
                || "GLOBAL".equalsIgnoreCase(signalGeoCountry);
    }

    private boolean matchesTargetSurface(List<String> targetSurfaceHints, EventTraits traits) {
        if (targetSurfaceHints == null || targetSurfaceHints.isEmpty()) {
            return false;
        }
        for (String targetSurface : targetSurfaceHints) {
            if (StringUtils.hasText(targetSurface) && targetSurface.equalsIgnoreCase(traits.pathCategory())) {
                return true;
            }
        }
        return false;
    }

    private List<String> matchedTagFacts(List<String> signalTags, EventTraits traits, boolean caseMode) {
        if (signalTags == null || signalTags.isEmpty() || traits.tags().isEmpty()) {
            return List.of();
        }
        List<String> facts = new ArrayList<>();
        for (String tag : signalTags) {
            if (!StringUtils.hasText(tag) || !traits.tags().contains(normalize(tag))) {
                continue;
            }
            String normalizedTag = normalize(tag);
            switch (normalizedTag) {
                case "failed_login_burst" -> facts.add(caseMode
                        ? "The current request includes repeated login failures, which matches prior reviewed cases."
                        : "The current request includes repeated login failures.");
                case "new_device" -> facts.add(caseMode
                        ? "The current request comes from a new device, matching prior reviewed cases."
                        : "The current request comes from a new device.");
                case "impossible_travel", "geo_velocity" -> facts.add(caseMode
                        ? "The current request carries impossible-travel context seen in prior reviewed cases."
                        : "The current request carries impossible-travel context.");
                case "sensitive_resource" -> facts.add(caseMode
                        ? "The current request touches a sensitive resource, similar to previous reviewed cases."
                        : "The current request is touching a sensitive resource.");
                case "session_integrity_risk" -> facts.add(caseMode
                        ? "The current request is tied to a session integrity anomaly seen in prior reviewed cases."
                        : "The current request is tied to a session integrity anomaly.");
                case "device_reputation_shift" -> facts.add(caseMode
                        ? "The current request includes a device or browser shift observed in prior reviewed cases."
                        : "The current request includes a device or browser shift.");
                case "privileged_flow" -> facts.add(caseMode
                        ? "The current request is part of a privileged flow that appears in prior reviewed cases."
                        : "The current request is part of a privileged flow.");
                default -> facts.add(caseMode
                        ? "The current request shares the historical case trait `" + normalizedTag + "`."
                        : "The current request shares campaign signal tag `" + normalizedTag + "`.");
            }
        }
        return facts.stream().distinct().toList();
    }

    private boolean isRecentlyObserved(LocalDateTime lastObservedAt) {
        if (lastObservedAt == null) {
            return false;
        }
        long hours = Math.max(0L, Duration.between(lastObservedAt, LocalDateTime.now()).toHours());
        return hours <= 24L;
    }

    private String geoFact(String geoCountry, boolean caseMode) {
        return caseMode
                ? "The current request originates from " + geoCountry + ", which overlaps with previous reviewed cases in the same region."
                : "The current request originates from " + geoCountry + ", which matches the active campaign region.";
    }

    private String surfaceFact(String pathCategory, boolean caseMode) {
        return caseMode
                ? "The current request targets the " + pathCategory + " surface, which appears in previous reviewed cases."
                : "The current request targets the " + pathCategory + " surface, which is one of the affected campaign surfaces.";
    }

    private String extractText(Map<String, Object> metadata, String key) {
        Object value = metadata.get(key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return StringUtils.hasText(text) ? text : null;
    }

    private boolean extractBoolean(Map<String, Object> metadata, String key) {
        Object value = metadata.get(key);
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (value instanceof String text) {
            return Boolean.parseBoolean(text);
        }
        return false;
    }

    private int extractInt(Map<String, Object> metadata, String key) {
        Object value = metadata.get(key);
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            try {
                return Integer.parseInt(text.trim());
            }
            catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    private String normalize(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private boolean containsText(String value, String... fragments) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        for (String fragment : fragments) {
            if (value.contains(fragment)) {
                return true;
            }
        }
        return false;
    }

    private record EventTraits(
            String requestPath,
            String pathCategory,
            String geoCountry,
            boolean newDevice,
            boolean impossibleTravel,
            boolean sensitiveResource,
            int failedLoginAttempts,
            boolean browserChanged,
            boolean osChanged,
            boolean sessionAnomaly,
            Set<String> tags) {
    }

    private record MatchFacts(
            List<String> facts,
            int matchingDimensions,
            boolean concreteOverlap) {
    }

    private record CandidateMatch(
            int matchedFactCount,
            int matchingDimensions,
            boolean recentlyObserved,
            int affectedTenantCount,
            int observationCount,
            LocalDateTime lastObservedAt,
            ThreatIntelligenceMatchContext.MatchedSignal match) {
    }

    private record KnowledgeCandidateMatch(
            int matchedFactCount,
            int matchingDimensions,
            boolean recentlyObserved,
            int affectedTenantCount,
            int observationCount,
            LocalDateTime lastObservedAt,
            ThreatKnowledgePackMatchContext.MatchedKnowledgeCase match) {
    }
}
