package io.contexa.contexacore.soar;

import io.contexa.contexacore.domain.SoarRequest;
import reactor.core.publisher.Mono;

public interface SoarLab {

    Mono<?> processAsync(SoarRequest request);
}
