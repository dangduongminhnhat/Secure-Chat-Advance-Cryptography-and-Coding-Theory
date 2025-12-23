package com.example.securechat;

public class Message {
    private String content;
    private boolean isFromUser;
    private long timestamp;

    public Message(String content, boolean isFromUser, long timestamp) {
        this.content = content;
        this.isFromUser = isFromUser;
        this.timestamp = timestamp;
    }

    // Getters
    public String getContent() { return content; }
    public boolean isFromUser() { return isFromUser; }
    public long getTimestamp() { return timestamp; }
}