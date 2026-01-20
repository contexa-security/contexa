package io.contexa.contexacore.autonomous;


public interface ISecurityPlaneAgent {
    
    void checkPendingApprovals();
    void performHealthCheck();
    void start();
    void stop();
    boolean isRunning();
    void resolveIncident(String incidentId, String resolvedBy, String resolutionMethod, boolean wasSuccessful);
}