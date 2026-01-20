package io.contexa.contexaiam.repository.impl;

import io.contexa.contexacommon.entity.behavior.BehaviorRealtimeCache;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;


@Repository
@Transactional
public class BehaviorRealtimeCacheRepositoryImpl {

    @PersistenceContext
    private EntityManager entityManager;

    
    public BehaviorRealtimeCache saveWithJsonHandling(BehaviorRealtimeCache cache) {
        String recentActivities = cache.getRecentActivities();
        String riskFactors = cache.getRiskFactors();

        
        if (recentActivities == null || recentActivities.isEmpty()) {
            recentActivities = "[]";
        }
        if (riskFactors == null || riskFactors.isEmpty()) {
            riskFactors = "{}";
        }

        String sql = """
            INSERT INTO behavior_realtime_cache
            (user_id, current_session_id, expires_at, last_activity_timestamp,
             recent_activities, risk_factors, session_ip, session_start_time, current_risk_score)
            VALUES
            (:userId, :sessionId, :expiresAt, :lastActivity,
             CAST(:recentActivities AS json), CAST(:riskFactors AS json),
             :sessionIp, :sessionStartTime, :riskScore)
            ON CONFLICT (user_id) DO UPDATE SET
                current_session_id = EXCLUDED.current_session_id,
                expires_at = EXCLUDED.expires_at,
                last_activity_timestamp = EXCLUDED.last_activity_timestamp,
                recent_activities = EXCLUDED.recent_activities,
                risk_factors = EXCLUDED.risk_factors,
                session_ip = EXCLUDED.session_ip,
                session_start_time = EXCLUDED.session_start_time,
                current_risk_score = EXCLUDED.current_risk_score
            """;

        entityManager.createNativeQuery(sql)
                .setParameter("userId", cache.getUserId())
                .setParameter("sessionId", cache.getCurrentSessionId())
                .setParameter("expiresAt", cache.getExpiresAt())
                .setParameter("lastActivity", cache.getLastActivityTimestamp())
                .setParameter("recentActivities", recentActivities)
                .setParameter("riskFactors", riskFactors)
                .setParameter("sessionIp", cache.getSessionIp())
                .setParameter("sessionStartTime", cache.getSessionStartTime())
                .setParameter("riskScore", cache.getCurrentRiskScore())
                .executeUpdate();

        return cache;
    }
}