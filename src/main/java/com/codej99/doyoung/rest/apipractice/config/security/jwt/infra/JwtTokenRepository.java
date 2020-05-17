package com.codej99.doyoung.rest.apipractice.config.security.jwt.infra;


import com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model.JwtTokenUtil;
import com.codej99.doyoung.rest.apipractice.entity.User;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.List;

@RequiredArgsConstructor
@Component
@Log
public class JwtTokenRepository {

    private final StringRedisTemplate redisTemplate;
    private final JwtTokenValidator jwtTokenValidator;


    public User getUserByToken(final String token) {

        final Claims claims = JwtTokenUtil.getClaimsByToken(token);
        final String uid = claims.getSubject();
        final Long msrl = claims.get("msrl", Long.class);
        final String password = claims.get("password", String.class);
        final List<String> roles = claims.get("roles", List.class);
        final String name = claims.get("name", String.class);

        final User user = User.builder()
                .roles(roles)
                .msrl(msrl)
                .password(password)
                .name(name)
                .build();

        log.info("uid :::" + uid);
        log.info("user ::: " + user);

        return user;
    }

    // Redis 에서 uid 가지고 refresh 가져옴
    public String getRefreshTokenByRedis(final String uid) {

        // Refresh Token  가져오기
        final String refreshTokenByRedis = redisTemplate.opsForValue().get(uid);

        // ACCESS TOKEN 을 갱신하려고 refreshToken 을 가져왔는데,
        // 기간이 만료되었을 때는 오류 처리를 해주는게 맞다.
        // Refresh Token 유효한 상태에서 AccessToken 을 연장 해주는 거니까
        // Token 자체의 유효성 검사
        jwtTokenValidator.validateToken(refreshTokenByRedis);

        return refreshTokenByRedis;
    }

    public String getSubjectByExpiredToken(final String token) {

        log.info("getSubjectByExpiredToken");
        // Expired 된 토큰 인 지 확인
        final Claims claims = jwtTokenValidator.validateExpiredToken(token);

        return claims.getSubject();
    }




}
