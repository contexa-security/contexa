package io.contexa.demo.comparison.manifest.evaluation.source;

import io.contexa.demo.comparison.manifest.evaluation.dto.FrozenReviewContract;

public interface ReviewContractQuery {

    FrozenReviewContract capture(String planKind);
}
