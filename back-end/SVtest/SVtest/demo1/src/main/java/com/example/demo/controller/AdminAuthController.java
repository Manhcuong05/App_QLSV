package com.example.demo.controller;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.dto.LoginRequest;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class AdminAuthController {

    private static final String ADMIN_EMAIL = "admin@gmail.com";
    private static final String ADMIN_PASSWORD = "123456";
    private static final String USER_EMAIL = "user@gmail.com";
    private static final String USER_PASSWORD = "123456";

    // Danh sách lưu token đang hợp lệ cho admin và user
    private static final Set<String> adminTokens = new HashSet<>();
    private static final Set<String> userTokens = new HashSet<>();

    // Danh sách lưu thông tin người dùng (chỉ làm ví dụ)
    private static final Map<String, String> registeredUsers = new HashMap<>();

    @PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
    String email = loginRequest.getEmail();
    String password = loginRequest.getPassword();

    // Admin
    if (ADMIN_EMAIL.equals(email) && ADMIN_PASSWORD.equals(password)) {
        String token = UUID.randomUUID().toString();
        adminTokens.add(token);
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Admin login successful");
        response.put("token", token);
        response.put("role", "admin");
        return ResponseEntity.ok(response);
    }

    // User hardcoded (có thể bỏ nếu dùng đăng ký)
    if (USER_EMAIL.equals(email) && USER_PASSWORD.equals(password)) {
        String token = UUID.randomUUID().toString();
        userTokens.add(token);
        Map<String, Object> response = new HashMap<>();
        response.put("message", "User login successful");
        response.put("token", token);
        response.put("role", "user");
        return ResponseEntity.ok(response);
    }

    // 🔥 Người dùng đăng ký từ /register
    if (registeredUsers.containsKey(email) && registeredUsers.get(email).equals(password)) {
        String token = UUID.randomUUID().toString();
        userTokens.add(token);
        Map<String, Object> response = new HashMap<>();
        response.put("message", "User login successful (from registered users)");
        response.put("token", token);
        response.put("role", "user");
        return ResponseEntity.ok(response);
    }

    // Nếu không khớp
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
}


    // Chức năng đăng xuất
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Missing or invalid Authorization header");
        }

        String token = authHeader.substring(7); // Bỏ "Bearer " phía trước

        // Kiểm tra token là của admin hay user
        if (adminTokens.contains(token)) {
            adminTokens.remove(token);
            Map<String, String> response = new HashMap<>();
            response.put("message", "Admin logged out successfully");
            return ResponseEntity.ok(response);
        } else if (userTokens.contains(token)) {
            userTokens.remove(token);
            Map<String, String> response = new HashMap<>();
            response.put("message", "User logged out successfully");
            return ResponseEntity.ok(response);
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
    }

    @PostMapping("/register")
public ResponseEntity<?> register(@RequestBody LoginRequest registerRequest) {
    String email = registerRequest.getEmail();
    String password = registerRequest.getPassword();

    // Check email đã tồn tại
    if (registeredUsers.containsKey(email)) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Email is already registered");
    }

    // Lưu tài khoản với vai trò mặc định là user
    registeredUsers.put(email, password);

    Map<String, Object> response = new HashMap<>();
    response.put("message", "Registration successful");
    response.put("role", "user");  // luôn là user
    return ResponseEntity.status(HttpStatus.CREATED).body(response);
}


    // Ví dụ API được bảo vệ (chỉ token hợp lệ mới xem được)
    @GetMapping("/secure-data")
    public ResponseEntity<?> getSecureData(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Missing or invalid Authorization header");
        }

        String token = authHeader.substring(7);

        // Kiểm tra token là của admin hay user
        if (adminTokens.contains(token)) {
            Map<String, String> data = new HashMap<>();
            data.put("secret", "This is admin-only data!");
            return ResponseEntity.ok(data);
        } else if (userTokens.contains(token)) {
            Map<String, String> data = new HashMap<>();
            data.put("secret", "This is user data!");
            return ResponseEntity.ok(data);
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
    }
}
