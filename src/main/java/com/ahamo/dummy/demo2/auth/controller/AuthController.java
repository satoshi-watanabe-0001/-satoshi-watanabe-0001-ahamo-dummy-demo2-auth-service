package com.ahamo.dummy.demo2.auth.controller;

import com.ahamo.dummy.demo2.auth.dto.*;
import com.ahamo.dummy.demo2.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        log.info("Login attempt for email: {}", loginRequest.getEmail());
        AuthResponse authResponse = authService.authenticateUser(loginRequest);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/login/contract")
    public ResponseEntity<AuthResponse> authenticateByContract(@Valid @RequestBody ContractLoginRequest contractLoginRequest) {
        log.info("Contract login attempt for contract: {}", contractLoginRequest.getContractNumber());
        AuthResponse authResponse = authService.authenticateByContract(contractLoginRequest);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        log.info("Token refresh attempt");
        AuthResponse authResponse = authService.refreshToken(refreshTokenRequest);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/verify")
    public ResponseEntity<String> verifyMFA(@Valid @RequestBody VerifyRequest verifyRequest) {
        log.info("MFA verification attempt");
        return ResponseEntity.ok("MFA verification endpoint - implementation pending");
    }
}
