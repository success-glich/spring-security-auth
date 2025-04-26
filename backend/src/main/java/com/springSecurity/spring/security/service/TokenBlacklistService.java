package com.springSecurity.spring.security.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class TokenBlacklistService {

    @Autowired
    private StringRedisTemplate redisTemplate;

    public static final String BLACKLIST_PREFIX = "blacklist:";

    public void blacklistToken(String token,long expirationInSeconds) {
          redisTemplate.opsForValue().set(BLACKLIST_PREFIX + token, "true", expirationInSeconds, TimeUnit.SECONDS);
    }

    public boolean isTokenBlacklisted(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(BLACKLIST_PREFIX+token));
    }
}
