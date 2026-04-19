package io.contexa.contexacore.autonomous.context.snapshot;

import java.util.LinkedHashMap;
import java.util.Map;

public record CurrentRequestSnapshot(
        String requestTimestamp,
        String currentAccessHour,
        String dayOfWeek,
        String authenticationType,
        String requestPath,
        String pathFamily,
        String actionFamily,
        String resourceFamily,
        String deviceBrowser,
        String deviceOs,
        String ipBand) {

    public Map<String, Object> toMap() {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("requestTimestamp", requestTimestamp);
        snapshot.put("currentAccessHour", currentAccessHour);
        snapshot.put("dayOfWeek", dayOfWeek);
        snapshot.put("authenticationType", authenticationType);
        snapshot.put("requestPath", requestPath);
        snapshot.put("pathFamily", pathFamily);
        snapshot.put("actionFamily", actionFamily);
        snapshot.put("resourceFamily", resourceFamily);
        snapshot.put("deviceBrowser", deviceBrowser);
        snapshot.put("deviceOs", deviceOs);
        snapshot.put("ipBand", ipBand);
        return snapshot;
    }
}
