package io.contexa.demo.identity.service;

import io.contexa.demo.identity.dto.IdentitySnapshotStatus;

public interface IdentitySnapshotService {

    void initialize();

    IdentitySnapshotStatus observation();
}
