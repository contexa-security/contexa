package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "xai")
public class XaiProperties {
    private boolean enabled = true;
    @NestedConfigurationProperty
    private DetailSettings detail = new DetailSettings();
    @NestedConfigurationProperty
    private CacheSettings cache = new CacheSettings();
    @NestedConfigurationProperty
    private FeatureSettings feature = new FeatureSettings();
    @NestedConfigurationProperty
    private ConfidenceSettings confidence = new ConfidenceSettings();
    @NestedConfigurationProperty
    private MaxSettings max = new MaxSettings();
    @NestedConfigurationProperty
    private VisualizationSettings visualization = new VisualizationSettings();

    @Data
    public static class DetailSettings { private String level = "MEDIUM"; }
    @Data
    public static class CacheSettings { private int ttlHours = 24; }
    @Data
    public static class FeatureSettings {
        @NestedConfigurationProperty
        private ImportanceSettings importance = new ImportanceSettings();
        @Data
        public static class ImportanceSettings { private double threshold = 0.1; }
    }
    @Data
    public static class ConfidenceSettings { private double threshold = 0.7; }
    @Data
    public static class MaxSettings { private int alternatives = 5; }
    @Data
    public static class VisualizationSettings { private boolean enabled = true; }
}
