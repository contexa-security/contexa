package io.contexa.demo.observation.decision.repository;

import io.contexa.demo.observation.decision.dto.NativeDecisionView;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
@Profile("baseline")
public class BaselineDecisionQuery implements NativeDecisionQuery {

    @Override
    public List<NativeDecisionView> find(UUID requestId) {
        return List.of();
    }
}
