package io.contexa.contexacore.autonomous.saas.learning.cohort;

import io.contexa.contexacore.autonomous.saas.dto.CohortSeedPackSnapshot;

public interface CohortSeedExpansionService {

    CohortSeedPackSnapshot expand(CohortSeedExpansionInput input);
}