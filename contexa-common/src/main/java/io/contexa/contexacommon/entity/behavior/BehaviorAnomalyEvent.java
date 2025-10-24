package io.contexa.contexacommon.entity.behavior;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "behavior_anomaly_events")
@Getter
@Setter
public class BehaviorAnomalyEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "event_timestamp", nullable = false)
    private LocalDateTime eventTimestamp;

    @Column(name = "activity", length = 500)
    private String activity;

    @Column(name = "remote_ip", length = 45)
    private String remoteIp;

    @Column(name = "anomaly_score", nullable = false)
    private double anomalyScore;

    @Column(name = "risk_level", length = 20)
    private String riskLevel;

    @Column(name = "anomaly_factors", columnDefinition = "JSON")
    private String anomalyFactors;

    @Column(name = "ai_analysis_id")
    private String aiAnalysisId;

    @Column(name = "ai_summary", columnDefinition = "TEXT")
    private String aiSummary;

    @Column(name = "ai_confidence")
    private Float aiConfidence;

    @Column(name = "admin_feedback", length = 20)
    private String adminFeedback;

    @Column(name = "feedback_comment", columnDefinition = "TEXT")
    private String feedbackComment;

    @Column(name = "feedback_timestamp")
    private LocalDateTime feedbackTimestamp;

    @Column(name = "feedback_by")
    private String feedbackBy;

    @Column(name = "action_taken", length = 100)
    private String actionTaken;

    @Column(name = "action_timestamp")
    private LocalDateTime actionTimestamp;
}
