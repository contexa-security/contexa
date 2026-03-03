package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.RequiredArgsConstructor;

import java.util.concurrent.ConcurrentHashMap;

@RequiredArgsConstructor
public class InMemoryThreatScoreUtil implements ThreatScoreUtil {

    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    private final ConcurrentHashMap<String, Double> threatScores = new ConcurrentHashMap<>();

    @Override
    public double getThreatScore(String userId) {
        if (userId == null || userId.isEmpty()) {
            return securityZeroTrustProperties.getThreat().getInitial();
        }

        Double score = threatScores.get(userId);
        return score != null ? score : securityZeroTrustProperties.getThreat().getInitial();
    }
}
