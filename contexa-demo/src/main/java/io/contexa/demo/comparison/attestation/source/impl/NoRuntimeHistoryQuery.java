package io.contexa.demo.comparison.attestation.source.impl;

import io.contexa.demo.comparison.attestation.dto.HistoryFingerprint;
import io.contexa.demo.comparison.attestation.source.InitialHistoryQuery;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("baseline")
public class NoRuntimeHistoryQuery implements InitialHistoryQuery {

    @Override
    public HistoryFingerprint capture(String username, HttpServletRequest request) {
        return new HistoryFingerprint("NOT_APPLICABLE", "BASELINE_AI_DISABLED", null, null, null,
                null, null, null, null);
    }
}
