package io.contexa.contexaiam.admin.promptquality.official.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

@RestController
@RequestMapping("/contexa/admin/api/prompt-quality")
public class PromptQualityOfficialConsoleApiController {

    private final PromptQualityOfficialConsoleViewAssembler views;

    public PromptQualityOfficialConsoleApiController(PromptQualityOfficialConsoleViewAssembler views) {
        this.views = views;
    }

    @GetMapping("/i18n")
    public Map<String, Object> i18n(
            @RequestParam(defaultValue = "enterprise.pqa.") String prefix,
            Locale locale) {
        Properties properties = new Properties();
        views.loadProperties(properties, "classpath*:i18n/messages.properties");
        if (locale != null && "ko".equalsIgnoreCase(locale.getLanguage())) {
            views.loadProperties(properties, "classpath*:i18n/messages_ko.properties");
        }
        Map<String, String> messages = new LinkedHashMap<>();
        properties.stringPropertyNames().stream()
                .filter(key -> key.startsWith(prefix))
                .sorted()
                .forEach(key -> messages.put(key, properties.getProperty(key)));
        return Map.of(
                "locale", locale == null ? Locale.getDefault().toLanguageTag() : locale.toLanguageTag(),
                "prefix", prefix,
                "messages", messages);
    }

    @GetMapping("/dashboard/summary")
    public Map<String, Object> dashboardSummary() {
        List<Map<String, Object>> resources = views.resourcesFromEvidence(200);
        List<Map<String, Object>> evidence =
                views.searchEvidence(null, null, null, null, null, null, null, null, 0, 200);
        long readyEvidence = evidence.stream()
                .filter(item -> Boolean.TRUE.equals(item.get("sealed"))
                        && Boolean.TRUE.equals(item.get("integrityValid")))
                .count();
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalResourceCount", resources.size());
        summary.put("zeroTrustEnabledCount", 0);
        summary.put("pendingCount", resources.size());
        summary.put("blockedCount", 0);
        summary.put("reverifyRequiredCount", 0);
        summary.put("expiringCertificateCount", 0);
        summary.put("readyRuntimeEvidenceCount", readyEvidence);
        summary.put("recurringIssues", List.of());
        return summary;
    }

    @GetMapping("/state-catalog")
    public Map<String, Object> stateCatalog() {
        return Map.of("states", views.stateCatalogRows());
    }
}