package io.contexa.contexacore.autonomous;

/**
 * SecurityPlaneAgent 인터페이스
 *
 * Spring AOP 프록시를 위한 인터페이스
 */
public interface ISecurityPlaneAgent {
    void checkForIncidents();
    void checkPendingApprovals();
    void performHealthCheck();
    void start();
    void stop();
    boolean isRunning();
    void resolveIncident(String incidentId, String resolvedBy, String resolutionMethod, boolean wasSuccessful);
}