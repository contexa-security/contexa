package io.contexa.demo.observation.decision.repository;

import io.contexa.demo.observation.decision.dto.NativeDecisionView;

import java.util.List;
import java.util.UUID;

public interface NativeDecisionQuery {

    List<NativeDecisionView> find(UUID requestId);
}
