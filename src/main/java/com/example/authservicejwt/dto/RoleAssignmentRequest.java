package com.example.authservicejwt.dto;

import lombok.Data;
import java.util.List;

@Data
public class RoleAssignmentRequest {
    private List<String> roles;
}
