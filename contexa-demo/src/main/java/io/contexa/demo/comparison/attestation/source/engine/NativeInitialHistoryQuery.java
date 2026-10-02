package io.contexa.demo.comparison.attestation.source.engine;

import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.demo.comparison.attestation.dto.HistoryFingerprint;
import io.contexa.demo.comparison.attestation.source.InitialHistoryQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.comparison.history.source.ContextHistoryQuery;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("contexa")
public class NativeInitialHistoryQuery implements InitialHistoryQuery {

    private final BaselineDataStore baselines;
    private final ZeroTrustActionRepository actions;
    private final DocumentCodec documents;
    private final ContextHistoryQuery contextHistory;

    public NativeInitialHistoryQuery(BaselineDataStore baselines, ZeroTrustActionRepository actions,
            DocumentCodec documents, ContextHistoryQuery contextHistory) {
        this.baselines = baselines;
        this.actions = actions;
        this.documents = documents;
        this.contextHistory = contextHistory;
    }

    @Override
    public HistoryFingerprint capture(String username, HttpServletRequest request) {
        try {
            var baseline = baselines.getUserBaseline(username);
            var analysis = actions.getAnalysisData(username);
            boolean originalAnalysis = analysis != null && analysis.requestId() != null;
            return new HistoryFingerprint("API_RETURN_OBSERVED", "NATIVE_USER_BASELINE_AND_ANALYSIS_READ",
                    baseline == null ? null : documents.hash(documents.write(baseline)),
                    baseline == null ? null : baseline.getUpdateCount(),
                    baseline == null ? null : baseline.getLastUpdated(),
                    originalAnalysis ? documents.hash(documents.write(analysis)) : null,
                    originalAnalysis ? analysis.requestId() : null, originalAnalysis ? analysis.action() : null,
                    contextHistory.capture(username, request));
        } catch (RuntimeException unavailable) {
            return new HistoryFingerprint("UNAVAILABLE", "NATIVE_USER_BASELINE_AND_ANALYSIS_READ",
                    null, null, null, null, null, null, null);
        }
    }
}
