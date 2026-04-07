package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;
import java.util.Map;

public class PendingAnomalyEventTriggerService {

    private final ZeroTrustEventPublisher zeroTrustEventPublisher;

    public PendingAnomalyEventTriggerService(ZeroTrustEventPublisher zeroTrustEventPublisher) {
        this.zeroTrustEventPublisher = zeroTrustEventPublisher;
    }

    public void publish(HttpServletRequest request, PendingAnomalyEvidenceReport report) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("triggerStage", "PRE_PROTECTABLE");
        payload.put("triggerSource", "PENDING_REDLINE");
        payload.put("action", ZeroTrustAction.PENDING_ANALYSIS.name());
        payload.put("contextBindingHash", report.contextBindingHash());
        payload.put("triggerStateKey", report.triggerStateKey());
        payload.put("reasonCodes", report.reasonCodes());
        payload.put("reasonSummary", report.reasonSummary());
        payload.put("anchorSignals", report.anchorSignals());
        payload.put("corroboratingSignals", report.corroboratingSignals());
        payload.put("riskSignature", report.riskSignature());
        payload.put("rawSignalSnapshot", report.rawSignalSnapshot());
        payload.put("requestId", report.requestId());
        payload.put("requestPath", report.requestPath());
        payload.put("httpMethod", report.httpMethod());
        payload.put("clientIp", report.clientIp());

        zeroTrustEventPublisher.publishPreProtectableThreat(report.userId(), payload);

        if (request != null) {
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGERED, true);
            if (report.requestId() != null) {
                request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_REQUEST_ID, report.requestId());
            }
            if (report.riskSignature() != null) {
                request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_RISK_SIGNATURE, report.riskSignature());
            }
        }
    }
}
