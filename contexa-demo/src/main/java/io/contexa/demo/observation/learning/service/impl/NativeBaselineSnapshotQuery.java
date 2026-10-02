package io.contexa.demo.observation.learning.service.impl;

import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.demo.observation.learning.dto.BaselineValueSnapshot;
import io.contexa.demo.observation.learning.service.BaselineSnapshotQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("contexa")
public class NativeBaselineSnapshotQuery implements BaselineSnapshotQuery {

    private final BaselineDataStore baselines;
    private final DocumentCodec documents;

    public NativeBaselineSnapshotQuery(BaselineDataStore baselines, DocumentCodec documents) {
        this.baselines = baselines;
        this.documents = documents;
    }

    @Override
    public BaselineValueSnapshot capture(BaselineVector value) {
        if (value == null) {
            return new BaselineValueSnapshot("NULL_RETURN_NOT_ABSENCE_PROOF", null, null, null);
        }
        return new BaselineValueSnapshot("VALUE_OBSERVED", documents.hash(documents.write(value)),
                value.getUpdateCount(), value.getLastUpdated());
    }

    @Override
    public BaselineValueSnapshot read(String username) {
        return capture(baselines.getUserBaseline(username));
    }
}
