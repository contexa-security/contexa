package io.contexa.contexacore.autonomous;

/**
 * SecurityPlaneAgent 인터페이스
 *
 * Spring AOP 프록시를 위한 인터페이스
 */
public interface ISecurityPlaneAgent {
    // checkForIncidents() 제거: startBackgroundMonitoring()과 중복
    void checkPendingApprovals();
    void performHealthCheck();
    void start();
    void stop();
    boolean isRunning();
    void resolveIncident(String incidentId, String resolvedBy, String resolutionMethod, boolean wasSuccessful);
}