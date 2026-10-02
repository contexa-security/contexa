package io.contexa.demo.comparison.attestation.source;

import io.contexa.demo.comparison.attestation.dto.HistoryFingerprint;
import jakarta.servlet.http.HttpServletRequest;

public interface InitialHistoryQuery {

    HistoryFingerprint capture(String username, HttpServletRequest request);
}
