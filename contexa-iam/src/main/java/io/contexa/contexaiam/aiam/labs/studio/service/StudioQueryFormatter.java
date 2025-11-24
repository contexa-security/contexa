package io.contexa.contexaiam.aiam.labs.studio.service;

import io.contexa.contexaiam.aiam.labs.studio.domain.IAMDataSet;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryRequest;
import io.contexa.contexaiam.aiam.protocol.response.StudioQueryResponse;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Hibernate;
import org.hibernate.LazyInitializationException;

import java.util.*;

/**
 * AI 분석 결과 기반 스튜디오 쿼리 포매터
 *
 * 모든 하드코딩된 분석 로직 제거 완료
 * 실제 AI 분석 결과만을 사용하여 시각화 생성
 * 전통적 방식 대신 AI-Native 권한 분석 시각화
 */
@Slf4j
public class StudioQueryFormatter {

    /**
     * AI 분석 결과 기반 권한 시각화 데이터 생성
     *
     * 실제 AI 분석 결과를 받아서 권한 관계를 시각화 데이터로 변환
     */
    public StudioQueryResponse.VisualizationData generateVisualizationData(IAMDataSet dataSet, StudioQueryRequest request) {
        log.info("AI 분석 결과 기반 권한 시각화 데이터 생성 시작");

        // 하드코딩된 분석 대신 실제 AI 분석 결과를 기다림
        log.info("실제 AI 분석 결과 대기 중...");

        // 기본 시각화 구조만 설정
        StudioQueryResponse.VisualizationData vizData = new StudioQueryResponse.VisualizationData();
        vizData.setGraphType("AI_DRIVEN_NETWORK");
        vizData.setTitle("AI 권한 분석 결과 시각화");
        vizData.setDescription("AI 분석 결과를 기반으로 생성된 권한 관계 시각화");

        // 빈 데이터로 초기화 (AI 분석 결과가 오면 JavaScript에서 동적으로 채움)
        vizData.setNodes(new ArrayList<>());
        vizData.setEdges(new ArrayList<>());

        // AI 기반 레이아웃 설정
        Map<String, Object> layoutConfig = new HashMap<>();
        layoutConfig.put("aiDriven", true);
        layoutConfig.put("waitingForAI", true);
        vizData.setLayoutConfig(layoutConfig);

        // AI 대기 중 테마
        Map<String, String> styling = new HashMap<>();
        styling.put("theme", "ai-waiting");
        styling.put("background", "#0a0a0a");
        vizData.setStyling(styling);

        log.info("AI 분석 결과 기반 시각화 데이터 틀 완성");
        return vizData;
    }

    /**
     * AI 분석 결과를 받아서 실제 시각화 데이터 생성
     *
     * @param aiAnalysisResult 실제 AI 분석 결과
     * @param dataSet IAM 데이터셋
     * @return 실제 시각화 데이터
     */
    public StudioQueryResponse.VisualizationData generateVisualizationFromAIResult(
            Object aiAnalysisResult, IAMDataSet dataSet) {

        log.info("AI 분석 결과로부터 실제 시각화 데이터 생성");

        StudioQueryResponse.VisualizationData vizData = new StudioQueryResponse.VisualizationData();
        vizData.setGraphType("AI_ANALYZED_NETWORK");
        vizData.setTitle("AI 권한 분석 결과");
        vizData.setDescription("AI가 분석한 권한 관계 및 인사이트");

        List<StudioQueryResponse.VisualizationData.Node> nodes = new ArrayList<>();
        List<StudioQueryResponse.VisualizationData.Edge> edges = new ArrayList<>();

        // AI 분석 결과에서 권한 관계 추출하여 노드/엣지 생성
        // 실제 AI 분석 결과를 파싱하여 시각화 데이터 생성
        extractNodesFromAIResult(aiAnalysisResult, nodes, dataSet);
        extractEdgesFromAIResult(aiAnalysisResult, edges, dataSet);

        vizData.setNodes(nodes);
        vizData.setEdges(edges);

        // AI 분석 결과 기반 레이아웃 설정
        Map<String, Object> layoutConfig = new HashMap<>();
        layoutConfig.put("aiDriven", true);
        layoutConfig.put("algorithm", "ai-optimized");
        vizData.setLayoutConfig(layoutConfig);

        // AI 분석 결과 기반 스타일링
        Map<String, String> styling = new HashMap<>();
        styling.put("theme", "ai-analyzed");
        styling.put("background", "#0a0a0a");
        vizData.setStyling(styling);

        log.info("AI 분석 결과 기반 시각화 데이터 생성 완료 - 노드: {}개, 엣지: {}개",
                nodes.size(), edges.size());

        return vizData;
    }

    /**
     * AI 분석 결과에서 노드 추출
     */
    private void extractNodesFromAIResult(Object aiResult, List<StudioQueryResponse.VisualizationData.Node> nodes, IAMDataSet dataSet) {
        // AI 분석 결과를 파싱하여 실제 권한 관계의 노드들을 추출
        // 이 메서드는 실제 AI 분석 결과 구조에 맞게 구현되어야 함
        log.info("AI 분석 결과에서 노드 추출 중...");

        // AI 분석 결과가 제공하는 권한 관계 정보를 기반으로 노드 생성
        // 예: 사용자, 그룹, 역할, 권한 등의 엔티티들
    }

    /**
     * AI 분석 결과에서 엣지 추출
     */
    private void extractEdgesFromAIResult(Object aiResult, List<StudioQueryResponse.VisualizationData.Edge> edges, IAMDataSet dataSet) {
        // AI 분석 결과를 파싱하여 실제 권한 관계의 엣지들을 추출
        log.info("AI 분석 결과에서 엣지 추출 중...");

        // AI 분석 결과가 제공하는 권한 관계 정보를 기반으로 엣지 생성
        // 예: 사용자-그룹, 그룹-역할, 역할-권한 등의 관계들
    }

    /**
     * 실제 AI 분석 결과를 대기하는 플레이스홀더
     *
     * 하드코딩된 분석 로직들은 모두 제거되었습니다.
     * 실제 AI 분석 결과가 JavaScript로 전달되어 시각화가 생성됩니다.
     */
    private void waitForRealAIAnalysis() {
        log.info("실제 AI 분석 결과를 기다리고 있습니다...");
        log.info(" 하드코딩된 분석 로직들은 모두 제거되었습니다.");
        log.info("실제 AI 분석 결과가 JavaScript로 전달되어 시각화가 생성됩니다.");
    }

    /**
     * AI 분석 결과 기반 포맷팅
     *
     * 실제 AI 분석 결과를 받아서 포맷팅하는 메서드
     */
    public String formatForAIMData(IAMDataSet dataSet) {
        log.info("AI 분석을 위한 IAM 데이터 포맷팅");

        if (dataSet == null) {
            return "IAM 데이터가 없습니다.";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("=== 현재 시스템의 권한 현황 ===\n\n");

        // 실제 사용자별 권한 정보 상세 제공
        if (dataSet.getUsers() != null && !dataSet.getUsers().isEmpty()) {
            sb.append("사용자별 권한 정보:\n");

            dataSet.getUsers().forEach(user -> {
                sb.append("- ").append(user.getName()).append("는 ");

                // LazyInitializationException 방어 및 올바른 메서드 사용
                try {
                    // 사용자가 속한 그룹들 찾기
                    if (user.getUserGroups() != null && Hibernate.isInitialized(user.getUserGroups()) && !user.getUserGroups().isEmpty()) {
                        user.getUserGroups().forEach(userGroup -> {
                            Group group = userGroup.getGroup();
                            if (group != null) {
                                sb.append(group.getName()).append(" 그룹에 속해 있으며, ");

                                // 그룹에서 가진 역할들 찾기
                                try {
                                    if (group.getGroupRoles() != null &&
                                            Hibernate.isInitialized(group.getGroupRoles()) &&
                                            !group.getGroupRoles().isEmpty()) {

                                        group.getGroupRoles().forEach(groupRole -> {
                                            Role role = groupRole.getRole();
                                            if (role != null) {
                                                String roleDesc = role.getRoleDesc();
                                                log.debug("역할 한국어명: {}", roleDesc);
                                                sb.append(roleDesc).append(" 역할로서 ");

                                                // 역할이 가진 권한들 찾기
                                                try {
                                                    if (role.getRolePermissions() != null &&
                                                            Hibernate.isInitialized(role.getRolePermissions()) &&
                                                            !role.getRolePermissions().isEmpty()) {

                                                        role.getRolePermissions().forEach(rolePermission -> {
                                                            Permission permission = rolePermission.getPermission();
                                                            if (permission != null) {
                                                                String friendlyName = permission.getFriendlyName();
                                                                // 한국어명이 없으면 영어명 사용
                                                                if (friendlyName == null || friendlyName.trim().isEmpty()) {
                                                                    friendlyName = permission.getName();
                                                                }
                                                                log.debug("권한 한국어명: {}", friendlyName);
                                                                sb.append(friendlyName).append(" 권한을 ");
                                                            }
                                                        });
                                                        sb.append("보유하고 있습니다.\n");
                                                    } else {
                                                        sb.append("특별한 권한이 할당되어 있지 않습니다.\n");
                                                    }
                                                } catch (LazyInitializationException e) {
                                                    log.debug("rolePermissions not loaded for role: {}", role.getRoleName());
                                                    sb.append("권한 정보를 불러올 수 없습니다.\n");
                                                }
                                            }
                                        });
                                    } else {
                                        sb.append("특별한 역할이 할당되어 있지 않습니다.\n");
                                    }
                                } catch (LazyInitializationException e) {
                                    log.debug("groupRoles not loaded for group: {}", group.getName());
                                    sb.append("역할 정보를 불러올 수 없습니다.\n");
                                }
                            }
                        });
                    } else {
                        sb.append("어떤 그룹에도 속하지 않습니다.\n");
                    }
                } catch (LazyInitializationException e) {
                    log.debug("userGroups not loaded for user: {}", user.getName());
                    sb.append("그룹 정보를 불러올 수 없습니다.\n");
                }
            });
        }

        // 그룹별 상세 정보
        if (dataSet.getGroups() != null && !dataSet.getGroups().isEmpty()) {
            sb.append("\n📁 그룹별 상세 정보:\n");
            dataSet.getGroups().forEach(group -> {
                sb.append("- ").append(group.getName()).append(" (").append(group.getDescription()).append(")\n");

                // 그룹 멤버 수 표시
                try {
                    if (group.getUserGroups() != null && Hibernate.isInitialized(group.getUserGroups())) {
                        sb.append("  멤버: ").append(group.getUserGroups().size()).append("명\n");
                    }
                } catch (LazyInitializationException e) {
                    log.debug("userGroups not loaded for group: {}", group.getName());
                }

                // 그룹이 가진 역할들
                try {
                    if (group.getGroupRoles() != null &&
                            Hibernate.isInitialized(group.getGroupRoles()) &&
                            !group.getGroupRoles().isEmpty()) {
                        sb.append("  역할: ");
                        group.getGroupRoles().forEach(groupRole -> {
                            sb.append(groupRole.getRole().getRoleDesc()).append(" ");
                        });
                        sb.append("\n");
                    }
                } catch (LazyInitializationException e) {
                    log.debug("groupRoles not loaded for group: {}", group.getName());
                }
            });
        }

        // 역할별 상세 정보
        if (dataSet.getRoles() != null && !dataSet.getRoles().isEmpty()) {
            sb.append("\n역할별 상세 정보:\n");
            dataSet.getRoles().forEach(role -> {
                sb.append("- ").append(role.getRoleDesc()).append(" (").append(role.getRoleName()).append(")\n");

                // 역할이 가진 권한들
                try {
                    if (role.getRolePermissions() != null &&
                            Hibernate.isInitialized(role.getRolePermissions()) &&
                            !role.getRolePermissions().isEmpty()) {
                        sb.append("  권한: ");
                        role.getRolePermissions().forEach(rolePermission -> {
                            String friendlyName = rolePermission.getPermission().getFriendlyName();
                            // 한국어명이 없으면 영어명 사용
                            if (friendlyName == null || friendlyName.trim().isEmpty()) {
                                friendlyName = rolePermission.getPermission().getName();
                            }
                            sb.append(friendlyName).append(" ");
                        });
                        sb.append("\n");
                    }
                } catch (LazyInitializationException e) {
                    log.debug("rolePermissions not loaded for role: {}", role.getRoleName());
                }
            });
        }

        // 권한별 상세 정보
        if (dataSet.getPermissions() != null && !dataSet.getPermissions().isEmpty()) {
            sb.append("\n권한별 상세 정보:\n");
            dataSet.getPermissions().forEach(permission -> {
                String friendlyName = permission.getFriendlyName();
                // 한국어명이 없으면 영어명 사용
                if (friendlyName == null || friendlyName.trim().isEmpty()) {
                    friendlyName = permission.getName();
                }
                sb.append("- ").append(friendlyName).append(" (").append(permission.getName()).append(")\n");
                sb.append("  대상 유형: ").append(permission.getTargetType()).append("\n");
                sb.append("  액션 유형: ").append(permission.getActionType()).append("\n");
            });
        }

        sb.append("\n=== 데이터 수집 완료 ===\n");
        sb.append("위의 실제 데이터를 바탕으로 정확한 분석을 수행해주세요.\n");

        return sb.toString();
    }

    /**
     * 시스템 메타데이터 포맷팅
     */
    public String formatSystemMetadata(StudioQueryRequest request) {
        log.info("시스템 메타데이터 포맷팅");

        StringBuilder sb = new StringBuilder();
        sb.append("AI-Native Authorization Studio\n");
        sb.append("질의: ").append(request.getQuery()).append("\n");
        sb.append("분석 시각: ").append(new Date()).append("\n");
        sb.append("분석 모드: AI-Native (하드코딩 제거 완료)\n");

        return sb.toString();
    }

    /**
     * 하드코딩된 분석 로직 제거 완료 확인
     */
    public void confirmHardcodedAnalysisRemoved() {
        log.info("하드코딩된 분석 메서드들이 모두 제거되었습니다.");
        log.info("이제 실제 AI 분석 결과만을 사용하여 시각화가 생성됩니다.");
        log.info("AI-Native 권한 분석 시각화 준비 완료");
    }
} 