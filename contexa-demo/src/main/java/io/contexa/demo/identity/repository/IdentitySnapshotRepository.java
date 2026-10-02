package io.contexa.demo.identity.repository;

import io.contexa.demo.identity.dto.IdentityAccount;
import io.contexa.demo.identity.dto.IdentitySnapshotStatus;

import java.util.List;

public interface IdentitySnapshotRepository {

    IdentitySnapshotStatus synchronize(String sourceDatabase, List<IdentityAccount> accounts);
}
