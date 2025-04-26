package com.springSecurity.spring.security.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;

@RestController

public class UserController {


    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    DataSource dataSource;

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/api/auth/register")
    public String registerUser(@RequestParam  String username,@RequestParam String password, @RequestParam String role) {
        JdbcUserDetailsManager userDetailsManager  = new JdbcUserDetailsManager(dataSource);
        if(userDetailsManager.userExists(username)){
            return "User already exists";
        }

        UserDetails userDetails = User.withUsername(username)
                .password(passwordEncoder.encode(password))
                .roles(role)
                .build();

        userDetailsManager.createUser(userDetails);

        return "User created successfully";
    }
}
