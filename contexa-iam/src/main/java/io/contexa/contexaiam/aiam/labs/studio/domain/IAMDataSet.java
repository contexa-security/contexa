package io.contexa.contexaiam.aiam.labs.studio.domain;

import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.Users;
import lombok.Data;

import java.util.List;


@Data
public class IAMDataSet {
    
    private List<Users> users;
    private List<Group> groups;
    private List<Role> roles;
    private List<Permission> permissions;
    
    private String error;
    private boolean success = true;
    
    
    public void setError(String error) {
        this.error = error;
        this.success = false;
    }
    
    
    public boolean isSuccess() {
        return success && error == null;
    }
    
    
    public boolean hasData() {
        return (users != null && !users.isEmpty()) ||
               (groups != null && !groups.isEmpty()) ||
               (roles != null && !roles.isEmpty()) ||
               (permissions != null && !permissions.isEmpty());
    }
    
    
    public String getSummary() {
        if (!isSuccess()) {
            return "데이터 수집 실패: " + error;
        }
        
        StringBuilder summary = new StringBuilder();
        summary.append("수집된 데이터: ");
        
        if (users != null) summary.append("사용자 ").append(users.size()).append("명, ");
        if (groups != null) summary.append("그룹 ").append(groups.size()).append("개, ");
        if (roles != null) summary.append("역할 ").append(roles.size()).append("개, ");
        if (permissions != null) summary.append("권한 ").append(permissions.size()).append("개, ");
        
        return summary.toString().replaceAll(", $", "");
    }
} 