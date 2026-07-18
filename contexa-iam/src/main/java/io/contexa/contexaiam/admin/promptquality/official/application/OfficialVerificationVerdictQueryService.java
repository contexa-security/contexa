package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationVerdict;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationSubject;

import java.util.Optional;

public interface OfficialVerificationVerdictQueryService {

    Optional<OfficialVerificationVerdict> findPersisted(
            String packageId,
            String aggregateRunId,
            OfficialVerificationSubject subject);
}
