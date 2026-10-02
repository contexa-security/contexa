package io.contexa.demo.comparison.manifest.source;

import io.contexa.demo.comparison.manifest.dto.NativeConfigurationSnapshot;

public interface NativeConfigurationQuery {

    NativeConfigurationSnapshot capture();
}
