package com.example.authservicejwt.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class AuthResponse {
    private String token;
    private String userId;
    private String username;
    private List<String> roles;
    private List<String> courseIds;
}
