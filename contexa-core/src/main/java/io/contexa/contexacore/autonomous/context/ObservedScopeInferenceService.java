package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.Optional;

public interface ObservedScopeInferenceService {

    Optional<CanonicalSecurityContext.ObservedScope> infer(SecurityEvent event, CanonicalSecurityContext context);
}
