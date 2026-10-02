package io.contexa.demo.identity.dto;

import java.util.UUID;

public record IdentitySnapshotStatus(
        String state,
        UUID snapshotId,
        String contentSha256,
        Integer accounts,
        String failureType
) {

}
