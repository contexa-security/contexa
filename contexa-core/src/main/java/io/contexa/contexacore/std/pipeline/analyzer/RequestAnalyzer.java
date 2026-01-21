package io.contexa.contexacore.std.pipeline.analyzer;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;

public interface RequestAnalyzer {

    <T extends DomainContext> RequestCharacteristics analyze(AIRequest<T> request);

    String getAnalyzerName();
}
