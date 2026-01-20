package io.contexa.contexacommon.domain.context;

import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.SecurityLevel;
import lombok.Getter;
import lombok.Setter;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Getter
@Setter
public class BehavioralAnalysisContext extends IAMContext {

    private static final String IAM_CONTEXT_TYPE = "BEHAVIOR_ANALYSIS";

    
    private String userId;
    private String currentActivity; 
    private String remoteIp;
    private String historicalBehaviorSummary;

    
    private List<String> recentActivitySequence = new ArrayList<>();  
    private List<Duration> activityIntervals = new ArrayList<>();     
    private String previousActivity;                                  
    private LocalDateTime lastActivityTime;                          
    private Duration timeSinceLastActivity;                          

    
    private String sessionFingerprint;                               
    private String deviceFingerprint;                               
    private String userAgent;                                        
    private String browserInfo;                                      
    private String osInfo;                                          
    private boolean isNewDevice;                                    
    private boolean isNewLocation;                                  

    
    private int dailyActivityCount;                                 
    private int hourlyActivityCount;                               
    private double activityVelocity;                               
    private Map<String, Integer> activityFrequency = new HashMap<>(); 

    
    private double behaviorAnomalyScore;                           
    private List<String> anomalyIndicators = new ArrayList<>();    
    private boolean hasRiskyPattern;                               
    private String riskCategory;                                   

    
    private String accessContext;                                  
    private String geoLocation;                                    
    private String networkSegment;                                 
    private boolean isVpnConnection;                               

    public BehavioralAnalysisContext() {
        this(SecurityLevel.STANDARD, AuditRequirement.DETAILED);
    }

    public BehavioralAnalysisContext(SecurityLevel securityLevel, AuditRequirement auditRequirement) {
        super(securityLevel, auditRequirement);
    }


    @Override
    public String getIAMContextType() {
        return IAM_CONTEXT_TYPE;
    }

    

    
    public void addActivityToSequence(String activity) {
        if (currentActivity != null && !currentActivity.equals(activity)) {
            previousActivity = currentActivity;
        }

        recentActivitySequence.add(activity);

        
        if (recentActivitySequence.size() > 20) {
            recentActivitySequence.remove(0);
        }

        
        if (lastActivityTime != null) {
            Duration interval = Duration.between(lastActivityTime, LocalDateTime.now());
            activityIntervals.add(interval);
            timeSinceLastActivity = interval;

            
            if (interval.toSeconds() > 0) {
                activityVelocity = 60.0 / interval.toSeconds();
            }
        }

        currentActivity = activity;
        lastActivityTime = LocalDateTime.now();

        
        activityFrequency.put(activity, activityFrequency.getOrDefault(activity, 0) + 1);
    }

    
    public void addAnomalyIndicator(String indicator) {
        if (!anomalyIndicators.contains(indicator)) {
            anomalyIndicators.add(indicator);
            hasRiskyPattern = true;
        }
    }

    
    public void generateSessionFingerprint() {
        StringBuilder sb = new StringBuilder();
        sb.append(userId != null ? userId : "unknown").append(":");
        sb.append(remoteIp != null ? remoteIp : "0.0.0.0").append(":");
        sb.append(userAgent != null ? userAgent.hashCode() : "0").append(":");
        sb.append(System.currentTimeMillis());

        this.sessionFingerprint = String.valueOf(sb.toString().hashCode());
    }

    
    public void generateDeviceFingerprint() {
        StringBuilder sb = new StringBuilder();
        sb.append(userAgent != null ? userAgent : "unknown").append(":");
        sb.append(browserInfo != null ? browserInfo : "unknown").append(":");
        sb.append(osInfo != null ? osInfo : "unknown").append(":");
        sb.append(remoteIp != null ? remoteIp.substring(0, remoteIp.lastIndexOf('.')) : "0.0.0");

        this.deviceFingerprint = String.valueOf(sb.toString().hashCode());
    }

    
    public boolean isNormalBehaviorPattern() {
        return behaviorAnomalyScore < 0.5 && !hasRiskyPattern;
    }

    
    public String getSequencePattern() {
        if (recentActivitySequence.isEmpty()) {
            return "NO_SEQUENCE";
        }
        return String.join(" -> ", recentActivitySequence);
    }

    
    public Map<String, Object> getContextSummary() {
        Map<String, Object> summary = new HashMap<>();
        summary.put("userId", userId);
        summary.put("currentActivity", currentActivity);
        summary.put("sequenceLength", recentActivitySequence.size());
        summary.put("anomalyScore", behaviorAnomalyScore);
        summary.put("hasRiskyPattern", hasRiskyPattern);
        summary.put("activityVelocity", activityVelocity);
        summary.put("isNewDevice", isNewDevice);
        summary.put("isNewLocation", isNewLocation);
        return summary;
    }
}
