package com.example.authservicejwt.service;

import com.example.authservicejwt.dto.AuthResponse;
import com.example.authservicejwt.dto.LoginRequest;
import com.example.authservicejwt.dto.RegisterRequest;
import com.example.authservicejwt.model.User;
import com.example.authservicejwt.repository.UserRepository;
import com.example.authservicejwt.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public Mono<AuthResponse> register(RegisterRequest request) {
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEmail(request.getEmail());
        user.setRoles(Arrays.asList("USER")); // Por defecto rol USER

        return userRepository.save(user)
                .map(savedUser -> {
                    String token = jwtUtil.generateToken(savedUser.getUsername(), savedUser.getRoles());
                    return AuthResponse.builder()
                            .token(token)
                            .userId(savedUser.getId())
                            .username(savedUser.getUsername())
                            .roles(savedUser.getRoles())
                            .courseIds(savedUser.getCourseIds())
                            .build();
                });
    }

    public Mono<AuthResponse> login(LoginRequest request) {
        return userRepository.findByUsername(request.getUsername())
                .filter(user -> passwordEncoder.matches(request.getPassword(), user.getPassword()))
                .map(user -> {
                    String token = jwtUtil.generateToken(user.getUsername(), user.getRoles());
                    return AuthResponse.builder()
                            .token(token)
                            .userId(user.getId())
                            .username(user.getUsername())
                            .roles(user.getRoles())
                            .courseIds(user.getCourseIds())
                            .build();
                });
    }

    public Mono<AuthResponse> validateToken(String token) {
        if (jwtUtil.validateToken(token)) {
            String username = jwtUtil.getUsernameFromToken(token);
            return userRepository.findByUsername(username)
                    .map(user -> AuthResponse.builder()
                            .token(token)
                            .userId(user.getId())
                            .username(user.getUsername())
                            .roles(user.getRoles())
                            .courseIds(user.getCourseIds())
                            .build());
        }
        return Mono.empty();
    }
    public Mono<AuthResponse> assignCoursesToUser(String userId, List<String> courseIds) {
        return userRepository.findById(userId)
                .flatMap(user -> {
                    // Obtener los cursos actuales o inicializar una nueva lista
                    List<String> currentCourses = user.getCourseIds() != null ?
                            new ArrayList<>(user.getCourseIds()) : new ArrayList<>();

                    // Agregar nuevos cursos sin duplicados
                    courseIds.forEach(courseId -> {
                        if (!currentCourses.contains(courseId)) {
                            currentCourses.add(courseId);
                        }
                    });

                    user.setCourseIds(currentCourses);

                    return userRepository.save(user)
                            .map(updatedUser -> {
                                String token = jwtUtil.generateToken(
                                        updatedUser.getUsername(),
                                        updatedUser.getRoles(),
                                        updatedUser.getCourseIds()
                                );

                                return AuthResponse.builder()
                                        .token(token)
                                        .userId(updatedUser.getId())
                                        .username(updatedUser.getUsername())
                                        .roles(updatedUser.getRoles())
                                        .courseIds(updatedUser.getCourseIds())
                                        .build();
                            });
                });
    }

    public Mono<AuthResponse> removeCourseFromUser(String userId, String courseId) {
        return userRepository.findById(userId)
                .flatMap(user -> {
                    List<String> currentCourses = user.getCourseIds();
                    if (currentCourses != null) {
                        currentCourses.remove(courseId);
                        user.setCourseIds(currentCourses);

                        return userRepository.save(user)
                                .map(updatedUser -> {
                                    String token = jwtUtil.generateToken(
                                            updatedUser.getUsername(),
                                            updatedUser.getRoles(),
                                            updatedUser.getCourseIds()
                                    );

                                    return AuthResponse.builder()
                                            .token(token)
                                            .userId(updatedUser.getId())
                                            .username(updatedUser.getUsername())
                                            .roles(updatedUser.getRoles())
                                            .courseIds(updatedUser.getCourseIds())
                                            .build();
                                });
                    }
                    return Mono.just(AuthResponse.builder()
                            .token(jwtUtil.generateToken(user.getUsername(), user.getRoles(), user.getCourseIds()))
                            .userId(user.getId())
                            .username(user.getUsername())
                            .roles(user.getRoles())
                            .courseIds(user.getCourseIds())
                            .build());
                });
    }
    public Mono<AuthResponse> updateUserRoles(String userId, List<String> newRoles) {
        // Validar que la lista de roles no esté vacía
        if (newRoles == null || newRoles.isEmpty()) {
            return Mono.error(new IllegalArgumentException("La lista de roles no puede estar vacía"));
        }

        // Validar que los roles sean válidos (opcional)
        List<String> validRoles = Arrays.asList("USER", "ADMIN", "INSTRUCTOR");
        if (!validRoles.containsAll(newRoles)) {
            return Mono.error(new IllegalArgumentException("Algunos roles no son válidos"));
        }

        return userRepository.findById(userId)
                .flatMap(user -> {
                    // Actualizar roles
                    user.setRoles(newRoles);

                    return userRepository.save(user)
                            .map(updatedUser -> {
                                String token = jwtUtil.generateToken(
                                        updatedUser.getUsername(),
                                        updatedUser.getRoles(),
                                        updatedUser.getCourseIds()
                                );

                                return AuthResponse.builder()
                                        .token(token)
                                        .userId(updatedUser.getId())
                                        .username(updatedUser.getUsername())
                                        .roles(updatedUser.getRoles())
                                        .courseIds(updatedUser.getCourseIds())
                                        .build();
                            });
                });
    }
}
