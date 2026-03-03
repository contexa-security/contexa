package io.contexa.contexacore.autonomous.store;

public interface BlockMfaStateStore {

    void setVerified(String userId);

    boolean isVerified(String userId);

    void setPending(String userId);

    void clearPending(String userId);

    int getFailCount(String userId);
}
