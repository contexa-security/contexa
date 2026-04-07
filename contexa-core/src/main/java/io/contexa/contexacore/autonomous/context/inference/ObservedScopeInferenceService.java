package io.contexa.contexacore.autonomous.context.inference;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.Optional;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;

public interface ObservedScopeInferenceService {

    Optional<CanonicalSecurityContext.ObservedScope> infer(SecurityEvent event, CanonicalSecurityContext context);
}
