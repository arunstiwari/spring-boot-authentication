package com.example.authenticationserver.service;

import com.example.authenticationserver.dto.request.SignupRequest;
import com.example.authenticationserver.dto.response.MessageResponse;
import com.example.authenticationserver.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class UserService {
    @Autowired
    UserRepository userRepository;

    public MessageResponse userExistsByUsername(SignupRequest signUpRequest){
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new MessageResponse("Error: Username is already taken!");
        }
        return null;
    }
    public MessageResponse userExistsByEmail(SignupRequest signUpRequest){

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new MessageResponse("Error: Email is already in use!");
        }
        return null;
    }
}
