package io.contexa.contexaiam.admin.web.monitoring.dto;

import java.util.List;


public record SecurityScoreDto(
        int score, 
        String summary, 
        List<ScoreFactor> factors 
) {
    
    public record ScoreFactor(String name, int value, double weight, String description) {}
}