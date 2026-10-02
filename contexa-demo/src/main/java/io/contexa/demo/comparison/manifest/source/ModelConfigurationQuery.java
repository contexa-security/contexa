package io.contexa.demo.comparison.manifest.source;

import io.contexa.demo.comparison.manifest.dto.NativeModelConfiguration;
import java.util.List;

public interface ModelConfigurationQuery {

    List<NativeModelConfiguration> capture();
}
