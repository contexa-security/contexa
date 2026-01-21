package io.contexa.contexacore.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Message {
    private String role;
    private String message;
    private LocalDateTime timestamp;
    
    public Message(String role, String message) {
        this.role = role;
        this.message = message;
        this.timestamp = LocalDateTime.now();
    }
    
    public String getRole() {
        return role;
    }
    
    public String getMessage() {
        return message;
    }
    
    public LocalDateTime getTimestamp() {
        return timestamp;
    }
}