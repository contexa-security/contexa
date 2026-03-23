package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;

public interface ThreatOutcomeForwardingService {

    void capture(AdminOverride adminOverride, SecurityEvent originalEvent);
}