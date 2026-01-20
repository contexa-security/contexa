package io.contexa.contexaiam.admin.web.monitoring.dto;


public record RiskIndicatorDto(
        String level, 
        String title, 
        String description, 
        String link 
) {}
