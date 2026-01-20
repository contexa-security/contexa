package io.contexa.contexacommon.domain;

import java.util.List;

public record TrustAssessment(
        double score, 
        List<String> riskTags, 
        String summary) {}