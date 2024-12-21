package com.example.authservicejwt.dto;

import lombok.Data;

import java.util.List;

@Data
public class CourseAssignmentRequest {
    private List<String> courseIds;
}