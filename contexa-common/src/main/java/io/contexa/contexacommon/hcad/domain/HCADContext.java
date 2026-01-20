package io.contexa.contexacommon.hcad.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.time.Instant;
import java.util.Map;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.stream.IntStream;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HCADContext {

    
    private String userId;
    private String sessionId;
    private String username;

    
    private String requestPath;
    private String httpMethod;
    private String remoteIp;
    private String userAgent;
    private String referer;
    private String eventType; 

    
    private Instant timestamp;
    private Long requestTime; 

    
    private String country;
    private String city;
    private Double latitude;
    private Double longitude;

    
    private Integer recentRequestCount; 
    private Long lastRequestInterval; 
    private Boolean isNewSession; 
    private Boolean isNewDevice; 
    private Boolean isNewUser; 

    
    private String authenticationMethod; 
    private Integer failedLoginAttempts; 
    private Double currentTrustScore; 
    private Boolean hasValidMFA; 

    
    private String resourceType; 
    private Boolean isSensitiveResource; 
    private String previousPath; 

    
    private Map<String, Object> additionalAttributes;

    
    
    private String[] previousActivities; 
    private String[] previousPaths; 
    private Long[] activityTimestamps; 
    private Double sequenceSimilarity; 

    
    private Long sessionStartTime; 
    private Integer pageViewCount; 
    private Double averagePageDuration; 
    private Integer clickCount; 
    private Integer scrollDepth; 

    
    private Double mouseMovementVelocity; 
    private Double keyboardTypingSpeed; 
    private Integer copyPasteCount; 
    private Boolean hasAutomatedPattern; 

    
    private Double networkLatency; 
    private Long bandwidthUsage; 
    private Integer httpStatusCode; 
    private String contentType; 
    private Long responseSize; 

    
    private Double cpuUsage; 
    private Double memoryUsage; 
    private Integer activeProcessCount; 
    private String[] runningServices; 

    
    private String tlsVersion; 
    private String cipherSuite; 
    private Boolean hasValidCertificate; 
    private String[] securityHeaders; 
    private Integer riskScore; 

    
    private String sourceIp; 
    private String deviceId; 
    private Double activityVelocity; 
    private List<String> recentActivitySequence; 
    private Map<String, Integer> activityFrequency; 
    private Double anomalyScore; 
    private Double trustScore; 

    
    @Builder.Default
    private Double baselineConfidence = 0.5; 
    private Double zScore; 
    private String deviceType; 
    private Double threatScore; 
    private Boolean isNewLocation; 

    
    public String toCompactString() {
        return String.format(
            "User:%s|IP:%s|Path:%s|Method:%s|UA:%s|Time:%s|Trust:%.2f|NewSession:%s|NewDevice:%s|NewUser:%s|RecentReqs:%d",
            userId != null ? userId : "anonymous",
            remoteIp,
            requestPath,
            httpMethod,
            userAgent != null ? userAgent.substring(0, Math.min(50, userAgent.length())) : "unknown",
            timestamp,
            currentTrustScore != null ? currentTrustScore : 0.5,
            isNewSession,
            isNewDevice,
            isNewUser,
            recentRequestCount != null ? recentRequestCount : 0
        );
    }

    
    public double[] toVector() {
        double[] vector = new double[384];
        int idx = 0;

        
        long epochSecond = timestamp.getEpochSecond();
        int hour = timestamp.atZone(java.time.ZoneId.systemDefault()).getHour();
        int dayOfWeek = timestamp.atZone(java.time.ZoneId.systemDefault()).getDayOfWeek().getValue();
        int dayOfMonth = timestamp.atZone(java.time.ZoneId.systemDefault()).getDayOfMonth();
        int month = timestamp.atZone(java.time.ZoneId.systemDefault()).getMonthValue();

        
        for (int i = 0; i < 24; i++) {
            vector[idx++] = (i == hour) ? 1.0 : 0.0;
        }

        
        for (int i = 1; i <= 7; i++) {
            vector[idx++] = (i == dayOfWeek) ? 1.0 : 0.0;
        }

        
        vector[idx++] = lastRequestInterval != null ?
            Math.tanh(lastRequestInterval / 1000.0) : 0.0; 

        
        
        
        int reqCount = recentRequestCount != null ? recentRequestCount : 0;
        vector[idx++] = Math.tanh(reqCount / 10.0);    
        vector[idx++] = Math.tanh(reqCount / 50.0);    
        vector[idx++] = Math.tanh(reqCount / 100.0);   
        vector[idx++] = Math.tanh(reqCount / 500.0);   
        vector[idx++] = Math.tanh(reqCount / 1000.0);  
        
        idx += 5;  

        
        vector[idx++] = isNewSession != null && isNewSession ? 1.0 : 0.0;
        vector[idx++] = isNewDevice != null && isNewDevice ? 1.0 : 0.0;
        vector[idx++] = sessionId != null ? 1.0 : 0.0;
        
        if (sessionId != null) {
            int hash = sessionId.hashCode();
            for (int i = 0; i < 7; i++) {
                vector[idx++] = ((hash >> (i * 4)) & 0xF) / 15.0;
            }
        } else {
            idx += 7;
        }

        
        String[] methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"};
        for (String method : methods) {
            vector[idx++] = method.equals(httpMethod) ? 1.0 : 0.0;
        }

        
        idx += 36;

        
        
        
        double trust = currentTrustScore != null ? currentTrustScore : 0.5;
        vector[idx++] = trust;
        vector[idx++] = trust * trust;  
        vector[idx++] = Math.sqrt(trust);  
        vector[idx++] = Math.log1p(trust);  
        
        idx += 6;  

        
        
        int failures = failedLoginAttempts != null ? failedLoginAttempts : 0;
        vector[idx++] = Math.tanh(failures / 5.0);  
        
        idx += 4;  
        for (int i = 0; i < 5; i++) {
            vector[idx++] = (failures == i) ? 1.0 : 0.0;  
        }

        
        String[] authMethods = {"password", "oauth", "mfa", "sso", "biometric",
                               "certificate", "token", "apikey", "ldap", "saml"};
        for (String method : authMethods) {
            vector[idx++] = method.equals(authenticationMethod) ? 1.0 : 0.0;
        }

        
        vector[idx++] = hasValidMFA != null && hasValidMFA ? 1.0 : 0.0;
        vector[idx++] = hasValidMFA == null ? 0.5 : 0.0;  
        vector[idx++] = isSensitiveResource != null && isSensitiveResource ? 1.0 : 0.0;
        vector[idx++] = isSensitiveResource == null ? 0.5 : 0.0;

        
        
        vector[idx++] = tlsVersion != null && tlsVersion.equals("TLSv1.3") ? 1.0 : 0.0;
        vector[idx++] = tlsVersion != null && tlsVersion.equals("TLSv1.2") ? 1.0 : 0.0;
        vector[idx++] = hasValidCertificate != null && hasValidCertificate ? 1.0 : 0.0;
        vector[idx++] = cipherSuite != null && cipherSuite.contains("AES256") ? 1.0 : 0.0;
        vector[idx++] = riskScore != null ? riskScore / 100.0 : 0.5;

        
        if (securityHeaders != null) {
            vector[idx++] = Arrays.asList(securityHeaders).contains("X-Frame-Options") ? 1.0 : 0.0;
            vector[idx++] = Arrays.asList(securityHeaders).contains("X-Content-Type-Options") ? 1.0 : 0.0;
            vector[idx++] = Arrays.asList(securityHeaders).contains("Strict-Transport-Security") ? 1.0 : 0.0;
            vector[idx++] = Arrays.asList(securityHeaders).contains("Content-Security-Policy") ? 1.0 : 0.0;
            vector[idx++] = Arrays.asList(securityHeaders).contains("X-XSS-Protection") ? 1.0 : 0.0;
        } else {
            idx += 5;
        }

        
        vector[idx++] = hasAutomatedPattern != null && hasAutomatedPattern ? 1.0 : 0.0;
        vector[idx++] = mouseMovementVelocity != null ? Math.tanh(mouseMovementVelocity / 1000.0) : 0.5;
        vector[idx++] = keyboardTypingSpeed != null ? Math.tanh(keyboardTypingSpeed / 100.0) : 0.5;
        vector[idx++] = copyPasteCount != null ? Math.tanh(copyPasteCount / 10.0) : 0.0;
        vector[idx++] = clickCount != null ? Math.tanh(clickCount / 50.0) : 0.5;

        
        idx += 10;

        
        
        if (remoteIp != null) {
            String[] parts = remoteIp.split("\\.");
            if (parts.length == 4) {
                for (String part : parts) {
                    try {
                        int octet = Integer.parseInt(part);
                        
                        vector[idx++] = octet / 255.0;
                        vector[idx++] = (octet & 0xF0) / 240.0;  
                        vector[idx++] = (octet & 0x0F) / 15.0;   
                        vector[idx++] = octet > 127 ? 1.0 : 0.0; 
                    } catch (NumberFormatException e) {
                        idx += 4;
                    }
                }
            } else {
                idx += 16;
            }
        } else {
            idx += 16;
        }

        
        if (city != null || country != null) {
            vector[idx++] = city != null ? city.hashCode() % 1000 / 1000.0 : 0.0;
            vector[idx++] = country != null ? country.hashCode() % 1000 / 1000.0 : 0.0;
        } else {
            idx += 2;
        }

        if (latitude != null && longitude != null) {
            vector[idx++] = (latitude + 90) / 180.0;  
            vector[idx++] = (longitude + 180) / 360.0; 
            vector[idx++] = Math.sin(Math.toRadians(latitude));
            vector[idx++] = Math.cos(Math.toRadians(latitude));
            vector[idx++] = Math.sin(Math.toRadians(longitude));
            vector[idx++] = Math.cos(Math.toRadians(longitude));
        } else {
            idx += 6;
        }

        
        vector[idx++] = referer != null && !referer.isEmpty() ? 1.0 : 0.0;
        vector[idx++] = referer != null && referer.contains(requestPath) ? 1.0 : 0.0;

        
        idx += 36;

        
        
        
        if (requestPath != null) {
            String[] pathParts = requestPath.split("/");
            vector[idx++] = Math.tanh(pathParts.length / 10.0);  
            
            
            idx += 8;  
            vector[idx++] = Math.tanh(requestPath.length() / 200.0);  
        } else {
            idx += 10;
        }

        
        String[] resourceTypes = {"admin", "api", "secure", "public", "general",
                                 "static", "dynamic", "protected", "system", "user"};
        for (String type : resourceTypes) {
            vector[idx++] = type.equals(resourceType) ? 1.0 : 0.0;
        }

        
        if (previousPath != null && requestPath != null) {
            vector[idx++] = previousPath.equals(requestPath) ? 1.0 : 0.0;
            vector[idx++] = previousPath.contains(requestPath) ? 1.0 : 0.0;
            vector[idx++] = requestPath.contains(previousPath) ? 1.0 : 0.0;
            vector[idx++] = Math.abs(previousPath.length() - requestPath.length()) / 100.0;
        } else {
            idx += 4;
        }

        
        idx += 40;

        
        
        
        if (userAgent != null) {
            
            
            idx += 17;  
            vector[idx++] = Math.tanh(userAgent.length() / 500.0);  
            vector[idx++] = Math.tanh(userAgent.length() / 100.0);  
            vector[idx++] = Math.tanh(userAgent.length() / 300.0);  
        } else {
            idx += 20;
        }

        
        idx += 44;

        
        
        if (additionalAttributes != null) {
            
            Object contentType = additionalAttributes.get("contentType");
            if (contentType != null) {
                String ct = contentType.toString().toLowerCase();
                vector[idx++] = ct.contains("json") ? 1.0 : 0.0;
                vector[idx++] = ct.contains("xml") ? 1.0 : 0.0;
                vector[idx++] = ct.contains("form") ? 1.0 : 0.0;
                vector[idx++] = ct.contains("multipart") ? 1.0 : 0.0;
                vector[idx++] = ct.contains("text") ? 1.0 : 0.0;
            } else {
                idx += 5;
            }

            
            Object secure = additionalAttributes.get("secure");
            vector[idx++] = secure != null && Boolean.TRUE.equals(secure) ? 1.0 : 0.0;

            
            Object queryString = additionalAttributes.get("queryString");
            vector[idx++] = queryString != null && !queryString.toString().isEmpty() ? 1.0 : 0.0;
        } else {
            idx += 8;
        }

        
        if (userId != null) {
            int userHash = userId.hashCode();
            for (int i = 0; i < 5; i++) {
                vector[idx++] = ((userHash >> (i * 6)) & 0x3F) / 63.0;
            }
        } else {
            idx += 5;
        }

        
        for (int i = idx; i < 384; i++) {
            vector[i] = 0.0;
        }

        return vector;
    }

    
    public String toJson() {
        try {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> jsonMap = new HashMap<>();

            
            jsonMap.put("userId", userId);
            jsonMap.put("sessionId", sessionId);
            jsonMap.put("username", username);
            jsonMap.put("requestPath", requestPath);
            jsonMap.put("httpMethod", httpMethod);
            jsonMap.put("remoteIp", remoteIp);
            jsonMap.put("sourceIp", getSourceIp());
            jsonMap.put("deviceId", deviceId);
            jsonMap.put("timestamp", timestamp != null ? timestamp.toString() : null);
            jsonMap.put("trustScore", getTrustScore());
            jsonMap.put("anomalyScore", anomalyScore);
            jsonMap.put("activityVelocity", getActivityVelocity());
            jsonMap.put("recentActivitySequence", getRecentActivitySequence());
            jsonMap.put("activityFrequency", getActivityFrequency());
            jsonMap.put("isNewSession", isNewSession);
            jsonMap.put("isNewDevice", isNewDevice());
            jsonMap.put("recentRequestCount", recentRequestCount);
            jsonMap.put("failedLoginAttempts", failedLoginAttempts);
            jsonMap.put("hasValidMFA", hasValidMFA);
            jsonMap.put("isSensitiveResource", isSensitiveResource);
            jsonMap.put("riskScore", riskScore);

            
            if (additionalAttributes != null) {
                jsonMap.put("additionalAttributes", additionalAttributes);
            }

            return mapper.writeValueAsString(jsonMap);
        } catch (JsonProcessingException e) {
            
            return String.format("{\"userId\":\"%s\",\"error\":\"JSON conversion failed\"}",
                               userId != null ? userId : "unknown");
        }
    }

    

    
    public String getSourceIp() {
        return sourceIp != null ? sourceIp : remoteIp;
    }

    
    public Double getTrustScore() {
        return trustScore != null ? trustScore : currentTrustScore;
    }

    
    public Double getActivityVelocity() {
        if (activityVelocity != null) {
            return activityVelocity;
        }
        
        if (recentRequestCount != null && recentRequestCount > 0) {
            return recentRequestCount / 5.0; 
        }
        return 0.0;
    }

    
    public List<String> getRecentActivitySequence() {
        if (recentActivitySequence != null) {
            return recentActivitySequence;
        }
        
        if (previousActivities != null) {
            return Arrays.asList(previousActivities);
        }
        return new ArrayList<>();
    }

    
    public Map<String, Integer> getActivityFrequency() {
        if (activityFrequency != null) {
            return activityFrequency;
        }
        
        return new HashMap<>();
    }

    
    public Double getAnomalyScore() {
        if (anomalyScore != null) {
            return anomalyScore;
        }
        
        if (currentTrustScore != null) {
            return 1.0 - currentTrustScore;
        }
        return 0.5;
    }

    
    public String getDeviceId() {
        if (deviceId != null) {
            return deviceId;
        }
        
        if (userAgent != null) {
            return String.valueOf(userAgent.hashCode());
        }
        return null;
    }

    
    public boolean isNewDevice() {
        return isNewDevice != null && isNewDevice;
    }

    
    public String getEventType() {
        if (httpMethod != null) {
            return httpMethod;
        }
        return "UNKNOWN";
    }

    
    public void setEventType(String eventType) {
        this.httpMethod = eventType;
    }

    
    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    
    public void setAdditionalData(Map<String, Object> data) {
        if (this.additionalAttributes == null) {
            this.additionalAttributes = new HashMap<>();
        }
        if (data != null) {
            this.additionalAttributes.putAll(data);
        }
    }

    
    public void setNewSession(boolean newSession) {
        this.isNewSession = newSession;
    }

    public void setNewDevice(boolean newDevice) {
        this.isNewDevice = newDevice;
    }

    public void setNewUser(boolean newUser) {
        this.isNewUser = newUser;
    }

    public void setSensitiveResource(boolean sensitiveResource) {
        this.isSensitiveResource = sensitiveResource;
    }

    public void setRecentRequestCount(int count) {
        this.recentRequestCount = count;
    }

    public void setLastRequestInterval(long interval) {
        this.lastRequestInterval = interval;
    }

    public void setCurrentTrustScore(double score) {
        this.currentTrustScore = score;
    }

    public void setFailedLoginAttempts(int attempts) {
        this.failedLoginAttempts = attempts;
    }

    public void setHasValidMFA(boolean hasValidMFA) {
        this.hasValidMFA = hasValidMFA;
    }

    public void setAuthenticationMethod(String method) {
        this.authenticationMethod = method;
    }

    public void setResourceType(String type) {
        this.resourceType = type;
    }

    public void setPreviousPath(String path) {
        this.previousPath = path;
    }

}