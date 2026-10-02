package io.contexa.demo.comparison.history.source;

import io.contexa.demo.comparison.history.dto.RoleScopeHistorySnapshot;

public interface RoleScopeHistoryQuery {

    RoleScopeHistorySnapshot capture(String tenantId, String username);
}
