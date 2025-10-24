package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.domain.entity.ThreatIndicator;

import java.util.List;
import java.util.Map;

/**
 * SOAR Context Provider Interface
 * 
 * Security Plane provides context to SOAR for AI decision making.
 * This interface follows the correct MCP mechanism where:
 * 1. Security Plane detects situation
 * 2. Provides context to SOAR
 * 3. SOAR requests appropriate tools from AI
 * 4. AI selects tools from MCP server
 * 5. ApprovalAwareToolCallingManagerDecorator handles high-risk tools
 */
public interface ISoarContextProvider {
    
    /**
     * Create SOAR context from security incident
     * 
     * @param incident The security incident
     * @return SOAR context with all necessary information
     */
    SoarContext createContextFromIncident(SecurityIncident incident);
    
    /**
     * Create SOAR context from security events
     * 
     * @param events List of security events
     * @return SOAR context with event information
     */
    SoarContext createContextFromEvents(List<SecurityEvent> events);
    
    /**
     * Create SOAR context from threat indicators
     * 
     * @param indicators List of threat indicators
     * @return SOAR context with threat information
     */
    SoarContext createContextFromThreatIndicators(List<ThreatIndicator> indicators);
    
    /**
     * Enrich context with additional information
     * 
     * @param context Existing SOAR context
     * @param additionalInfo Additional information to add
     * @return Enriched SOAR context
     */
    SoarContext enrichContext(SoarContext context, Map<String, Object> additionalInfo);
    
    /**
     * Create emergency context for critical situations
     * 
     * @param description Description of emergency
     * @param severity Severity level
     * @return Emergency SOAR context
     */
    SoarContext createEmergencyContext(String description, String severity);
}