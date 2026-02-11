package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "memory")
public class MemoryProperties {
    @NestedConfigurationProperty
    private SystemSettings system = new SystemSettings();
    @NestedConfigurationProperty
    private StmSettings stm = new StmSettings();
    @NestedConfigurationProperty
    private LtmSettings ltm = new LtmSettings();
    @NestedConfigurationProperty
    private WmSettings wm = new WmSettings();
    @NestedConfigurationProperty
    private ConsolidationSettings consolidation = new ConsolidationSettings();

    @Data
    public static class SystemSettings { private boolean enabled = true; }
    @Data
    public static class StmSettings { private int capacity = 1000; private int ttlMinutes = 30; }
    @Data
    public static class LtmSettings { private double consolidationThreshold = 0.7; private int retentionDays = 365; }
    @Data
    public static class WmSettings { private int capacity = 100; private int ttlSeconds = 300; }
    @Data
    public static class ConsolidationSettings { private int intervalMinutes = 15; }
}
