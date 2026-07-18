package io.contexa.contexaiam.admin.promptquality.official.web.model;

import java.util.List;

public record PromptQualityNavigationItem(
        String label,
        String href,
        String responsibility,
        boolean active,
        List<PromptQualityNavigationItem> children) {
}
