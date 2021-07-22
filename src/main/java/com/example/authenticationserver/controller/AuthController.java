package com.example.authenticationserver.controller;

import com.example.authenticationserver.dto.request.LoginRequest;
import com.example.authenticationserver.dto.request.SignupRequest;
import com.example.authenticationserver.dto.response.JwtResponse;
import com.example.authenticationserver.dto.response.MessageResponse;
import com.example.authenticationserver.service.AuthenticationService;
import com.example.authenticationserver.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {

    @Autowired
    AuthenticationService authenticationService;

    @Autowired
    UserService userService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        JwtResponse response = authenticationService.authenticateUser(loginRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        log.info(" signupRequest : {}", signUpRequest);
        MessageResponse response = userService.userExistsByUsername(signUpRequest);
        if (response != null){
            return ResponseEntity
                    .badRequest()
                    .body(response);
        }
        MessageResponse resp = userService.userExistsByEmail(signUpRequest);
        if (response != null){
            return ResponseEntity
                    .badRequest()
                    .body(resp);
        }

        authenticationService.registerUser(signUpRequest);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
