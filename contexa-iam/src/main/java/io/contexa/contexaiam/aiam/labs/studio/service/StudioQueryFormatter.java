package io.contexa.contexaiam.aiam.labs.studio.service;

import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexaiam.aiam.labs.studio.domain.IAMDataSet;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryRequest;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Hibernate;
import org.hibernate.LazyInitializationException;

import java.util.Date;

@Slf4j
public class StudioQueryFormatter {

    public String formatForAIMData(IAMDataSet dataSet) {
        
        if (dataSet == null) {
            return "IAM 데이터가 없습니다.";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("=== 현재 시스템의 권한 현황 ===\n\n");

        if (dataSet.getUsers() != null && !dataSet.getUsers().isEmpty()) {
            sb.append("사용자별 권한 정보:\n");

            dataSet.getUsers().forEach(user -> {
                sb.append("- ").append(user.getName()).append("는 ");

                try {
                    
                    if (user.getUserGroups() != null && Hibernate.isInitialized(user.getUserGroups()) && !user.getUserGroups().isEmpty()) {
                        user.getUserGroups().forEach(userGroup -> {
                            Group group = userGroup.getGroup();
                            if (group != null) {
                                sb.append(group.getName()).append(" 그룹에 속해 있으며, ");

                                try {
                                    if (group.getGroupRoles() != null &&
                                            Hibernate.isInitialized(group.getGroupRoles()) &&
                                            !group.getGroupRoles().isEmpty()) {

                                        group.getGroupRoles().forEach(groupRole -> {
                                            Role role = groupRole.getRole();
                                            if (role != null) {
                                                String roleDesc = role.getRoleDesc();
                                                                                                sb.append(roleDesc).append(" 역할로서 ");

                                                try {
                                                    if (role.getRolePermissions() != null &&
                                                            Hibernate.isInitialized(role.getRolePermissions()) &&
                                                            !role.getRolePermissions().isEmpty()) {

                                                        role.getRolePermissions().forEach(rolePermission -> {
                                                            Permission permission = rolePermission.getPermission();
                                                            if (permission != null) {
                                                                String friendlyName = permission.getFriendlyName();
                                                                
                                                                if (friendlyName == null || friendlyName.trim().isEmpty()) {
                                                                    friendlyName = permission.getName();
                                                                }
                                                                                                                                sb.append(friendlyName).append(" 권한을 ");
                                                            }
                                                        });
                                                        sb.append("보유하고 있습니다.\n");
                                                    } else {
                                                        sb.append("특별한 권한이 할당되어 있지 않습니다.\n");
                                                    }
                                                } catch (LazyInitializationException e) {
                                                                                                        sb.append("권한 정보를 불러올 수 없습니다.\n");
                                                }
                                            }
                                        });
                                    } else {
                                        sb.append("특별한 역할이 할당되어 있지 않습니다.\n");
                                    }
                                } catch (LazyInitializationException e) {
                                                                        sb.append("역할 정보를 불러올 수 없습니다.\n");
                                }
                            }
                        });
                    } else {
                        sb.append("어떤 그룹에도 속하지 않습니다.\n");
                    }
                } catch (LazyInitializationException e) {
                                        sb.append("그룹 정보를 불러올 수 없습니다.\n");
                }
            });
        }

        if (dataSet.getGroups() != null && !dataSet.getGroups().isEmpty()) {
            sb.append("\n📁 그룹별 상세 정보:\n");
            dataSet.getGroups().forEach(group -> {
                sb.append("- ").append(group.getName()).append(" (").append(group.getDescription()).append(")\n");

                try {
                    if (group.getUserGroups() != null && Hibernate.isInitialized(group.getUserGroups())) {
                        sb.append("  멤버: ").append(group.getUserGroups().size()).append("명\n");
                    }
                } catch (LazyInitializationException e) {
                                    }

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
                                    }
            });
        }

        if (dataSet.getRoles() != null && !dataSet.getRoles().isEmpty()) {
            sb.append("\n역할별 상세 정보:\n");
            dataSet.getRoles().forEach(role -> {
                sb.append("- ").append(role.getRoleDesc()).append(" (").append(role.getRoleName()).append(")\n");

                try {
                    if (role.getRolePermissions() != null &&
                            Hibernate.isInitialized(role.getRolePermissions()) &&
                            !role.getRolePermissions().isEmpty()) {
                        sb.append("  권한: ");
                        role.getRolePermissions().forEach(rolePermission -> {
                            String friendlyName = rolePermission.getPermission().getFriendlyName();
                            
                            if (friendlyName == null || friendlyName.trim().isEmpty()) {
                                friendlyName = rolePermission.getPermission().getName();
                            }
                            sb.append(friendlyName).append(" ");
                        });
                        sb.append("\n");
                    }
                } catch (LazyInitializationException e) {
                                    }
            });
        }

        if (dataSet.getPermissions() != null && !dataSet.getPermissions().isEmpty()) {
            sb.append("\n권한별 상세 정보:\n");
            dataSet.getPermissions().forEach(permission -> {
                String friendlyName = permission.getFriendlyName();
                
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

    public String formatSystemMetadata(StudioQueryRequest request) {
        
        StringBuilder sb = new StringBuilder();
        sb.append("AI-Native Authorization Studio\n");
        sb.append("질의: ").append(request.getNaturalLanguageQuery()).append("\n");
        sb.append("분석 시각: ").append(new Date()).append("\n");
        sb.append("분석 모드: AI-Native (하드코딩 제거 완료)\n");

        return sb.toString();
    }
}