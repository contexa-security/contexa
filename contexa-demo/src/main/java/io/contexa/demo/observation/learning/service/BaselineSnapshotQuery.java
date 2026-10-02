package io.contexa.demo.observation.learning.service;

import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.demo.observation.learning.dto.BaselineValueSnapshot;

public interface BaselineSnapshotQuery {

    BaselineValueSnapshot capture(BaselineVector value);

    BaselineValueSnapshot read(String username);
}
