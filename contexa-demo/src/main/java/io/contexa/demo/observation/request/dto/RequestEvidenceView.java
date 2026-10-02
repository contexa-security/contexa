package io.contexa.demo.observation.request.dto;

import io.contexa.demo.observation.decision.dto.NativeDecisionView;
import io.contexa.demo.observation.download.dto.DownloadEvidence;
import io.contexa.demo.observation.engine.dto.EngineObservation;
import io.contexa.demo.observation.health.dto.CollectionHealth;
import io.contexa.demo.observation.http.dto.BusinessHttpObservation;
import io.contexa.demo.observation.model.dto.ModelBoundaryEvidence;
import io.contexa.demo.observation.provider.dto.ProviderHttpEvidence;
import io.contexa.demo.work.request.dto.WorkRequestSnapshot;

import java.util.List;

public record RequestEvidenceView(
        String role,
        BusinessHttpObservation http,
        WorkRequestSnapshot snapshot,
        List<EngineObservation> analysisEvents,
        List<NativeDecisionView> decisions,
        String providerCaptureState,
        String decisionReadState,
        DownloadEvidence download,
        CollectionHealth collectionHealth,
        ModelBoundaryEvidence modelBoundary,
        ProviderHttpEvidence providerHttp) {
}
