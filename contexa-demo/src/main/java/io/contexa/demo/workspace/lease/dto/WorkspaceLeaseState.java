package io.contexa.demo.workspace.lease.dto;

import java.time.Instant;

public record WorkspaceLeaseState(boolean enabled, Instant serverTime, WorkspaceLease lease) {

}
