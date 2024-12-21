package com.example.authservicejwt.controller;

import com.example.authservicejwt.dto.*;
import com.example.authservicejwt.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public Mono<ResponseEntity<AuthResponse>> register(@RequestBody RegisterRequest request) {
        return authService.register(request)
                .map(response -> ResponseEntity.ok(response))
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.BAD_REQUEST).build());
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(@RequestBody LoginRequest request) {
        return authService.login(request)
                .map(response -> ResponseEntity.ok(response))
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    @GetMapping("/validate")
    public Mono<ResponseEntity<AuthResponse>> validateToken(@RequestHeader("Authorization") String token) {
        return authService.validateToken(token.replace("Bearer ", ""))
                .map(response -> ResponseEntity.ok(response))
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }
    @PatchMapping("/users/{userId}/courses")
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal")
    public Mono<ResponseEntity<AuthResponse>> assignCourses(
            @PathVariable String userId,
            @RequestBody CourseAssignmentRequest request) {
        return authService.assignCoursesToUser(userId, request.getCourseIds())
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/users/{userId}/courses/{courseId}")
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal")
    public Mono<ResponseEntity<AuthResponse>> removeCourse(
            @PathVariable String userId,
            @PathVariable String courseId) {
        return authService.removeCourseFromUser(userId, courseId)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }
    @PatchMapping("/users/{userId}/roles")
    @PreAuthorize("hasRole('ADMIN')")  // Solo administradores pueden cambiar roles
    public Mono<ResponseEntity<AuthResponse>> updateRoles(
            @PathVariable String userId,
            @RequestBody RoleAssignmentRequest request) {
        return authService.updateUserRoles(userId, request.getRoles())
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }
}