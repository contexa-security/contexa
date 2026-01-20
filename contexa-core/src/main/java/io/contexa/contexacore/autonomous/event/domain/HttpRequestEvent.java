package io.contexa.contexacore.autonomous.event.domain;

import io.contexa.contexacore.autonomous.event.decision.EventTier;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.springframework.security.core.Authentication;

import java.time.LocalDateTime;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class HttpRequestEvent {

    private String eventId;
    private LocalDateTime eventTimestamp;
    private String userId;
    private String sourceIp;
    private String requestUri;
    private String httpMethod;
    private int statusCode;
    private String userAgent;  
    private Authentication authentication;

    
    private Boolean hcadIsAnomaly;         
    private Double hcadAnomalyScore;       
    private String hcadAction;             

    
    private boolean isAnonymous;
    private EventTier eventTier;          
    private Double riskScore;              
    private Double trustScore;             
    private Double ipThreatScore;          

    
    private Boolean isNewSession;          
    private Boolean isNewUser;             
    private Boolean isNewDevice;           
    private Integer recentRequestCount;    

    
    private String authMethod;             
}
