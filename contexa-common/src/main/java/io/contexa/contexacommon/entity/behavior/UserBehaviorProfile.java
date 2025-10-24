package io.contexa.contexacommon.entity.behavior;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_behavior_profiles")
@Getter
@Setter
public class UserBehaviorProfile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "profile_type", nullable = false, length = 50)
    private String profileType;

    @Column(name = "vector_cluster_id")
    private String vectorClusterId;

    @Column(name = "cluster_centroid_vector", columnDefinition = "TEXT")
    private String clusterCentroidVector;

    @Column(name = "cluster_size")
    private Integer clusterSize = 0;

    @Column(name = "normal_range_metadata", columnDefinition = "JSON")
    private String normalRangeMetadata;

    @Column(name = "common_activities", columnDefinition = "JSON")
    private String commonActivities;

    @Column(name = "common_ip_ranges", columnDefinition = "JSON")
    private String commonIpRanges;

    @Column(name = "last_updated")
    private LocalDateTime lastUpdated = LocalDateTime.now();

    @Column(name = "confidence_score")
    private Float confidenceScore = 0.5f;

    @Column(name = "learning_count")
    private Integer learningCount = 0;
}