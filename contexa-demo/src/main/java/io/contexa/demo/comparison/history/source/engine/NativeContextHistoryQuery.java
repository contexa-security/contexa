package io.contexa.demo.comparison.history.source.engine;

import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.demo.comparison.history.dto.ContextHistorySnapshot;
import io.contexa.demo.comparison.history.dto.HistorySequenceFingerprint;
import io.contexa.demo.comparison.history.source.ContextHistoryQuery;
import io.contexa.demo.comparison.history.source.RoleScopeHistoryQuery;
import io.contexa.demo.comparison.history.source.SessionClockQuery;
import io.contexa.demo.observation.learning.dto.BaselineValueSnapshot;
import io.contexa.demo.observation.learning.service.BaselineSnapshotQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Supplier;

@Component
@Profile("contexa")
public class NativeContextHistoryQuery implements ContextHistoryQuery {

    private final SecurityContextDataStore store;
    private final BaselineDataStore baselines;
    private final BaselineSnapshotQuery fingerprints;
    private final SessionClockQuery clocks;
    private final RoleScopeHistoryQuery roleScopes;
    private final DocumentCodec documents;
    private final TieredStrategyProperties properties;

    public NativeContextHistoryQuery(SecurityContextDataStore store, BaselineDataStore baselines,
            BaselineSnapshotQuery fingerprints, SessionClockQuery clocks, DocumentCodec documents,
            TieredStrategyProperties properties, RoleScopeHistoryQuery roleScopes) {
        this.store = store;
        this.baselines = baselines;
        this.fingerprints = fingerprints;
        this.clocks = clocks;
        this.roleScopes = roleScopes;
        this.documents = documents;
        this.properties = properties;
    }

    @Override
    public ContextHistorySnapshot capture(String username, HttpServletRequest request) {
        Instant start = Instant.now();
        var nativeRequest = RequestInfoExtractor.extract(request, properties.getSecurity());
        String session = nativeRequest.getSessionId();
        String tenant = nativeRequest.getTenantId();
        String organization = nativeRequest.getOrganizationId();
        Map<String, HistorySequenceFingerprint> sequences = new TreeMap<>();
        if (session != null && !session.isBlank()) {
            sequences.put("sessionActions", sequence(() -> store.getRecentSessionActions(session, 101), 100));
            sequences.put("sessionNarrativeActions", sequence(() -> store.getRecentSessionNarrativeActionFamilies(session, 101), 100));
            sequences.put("sessionProtectableAccesses", sequence(() -> store.getRecentSessionProtectableAccesses(session, 101), 100));
            sequences.put("sessionIntervals", sequence(() -> store.getRecentSessionRequestIntervals(session, 101), 100));
        }
        sequences.put("personalWorkHistory", sequence(() -> store.getRecentWorkProfileObservations(tenant, username, 5001), 5000));
        sequences.put("permissionChanges", sequence(() -> store.getRecentPermissionChangeObservations(tenant, username, 201), 200));
        BaselineValueSnapshot organizationBaseline = organization == null ? null
                : fingerprints.capture(baselines.getOrganizationBaseline(organization));
        var clock = clocks.capture(session);
        var roleScope = roleScopes.capture(tenant, username);
        boolean available = "READ_COMPLETED".equals(clock.state())
                && ("API_RETURN_OBSERVED".equals(roleScope.state())
                || "NO_STORED_SCOPE_RETURNED".equals(roleScope.state()))
                && sequences.values().stream().allMatch(value -> "API_RETURN_OBSERVED".equals(value.state()));
        return new ContextHistorySnapshot(available ? "API_RETURNS_OBSERVED" : "INCOMPLETE", start, Instant.now(),
                "NATIVE_REQUEST_INFO_EXTRACTOR_CURRENT_ATTESTATION_NOT_PAST_EVENT", hash(session), hash(tenant),
                hash(organization), organization == null ? "NO_ORGANIZATION_IN_NATIVE_REQUEST" : "NATIVE_ORGANIZATION_OBSERVED",
                organizationBaseline, clock, Map.copyOf(sequences),
                "SEPARATE_NATIVE_READS_NOT_ATOMIC_SNAPSHOT_EMPTY_RETURN_IS_NOT_ABSENCE_PROOF", roleScope);
    }

    private HistorySequenceFingerprint sequence(Supplier<? extends List<?>> query, int limit) {
        try {
            var values = query.get();
            if (values == null) {
                return new HistorySequenceFingerprint("UNAVAILABLE", null, limit, null);
            }
            if (values.size() > limit) {
                return new HistorySequenceFingerprint("SIZE_LIMIT", values.size(), limit, null);
            }
            return new HistorySequenceFingerprint("API_RETURN_OBSERVED", values.size(), limit,
                    documents.hash(documents.write(values)));
        } catch (RuntimeException unavailable) {
            return new HistorySequenceFingerprint("UNAVAILABLE", null, limit, null);
        }
    }

    private String hash(String value) {
        return value == null ? null : documents.hash(value);
    }
}
