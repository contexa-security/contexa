package io.contexa.demo.comparison.manifest.source.impl;

import io.contexa.demo.comparison.manifest.dto.NativeConfigurationSnapshot;
import io.contexa.demo.comparison.manifest.source.NativeConfigurationQuery;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.util.List;
import java.util.Map;

@Component
@Profile("baseline")
public class NoAiConfigurationQuery implements NativeConfigurationQuery {

    @Override
    public NativeConfigurationSnapshot capture() {
        return new NativeConfigurationSnapshot("NOT_APPLICABLE", "BASELINE_AI_DISABLED",
                List.of(), Map.of(), null, List.of());
    }
}
