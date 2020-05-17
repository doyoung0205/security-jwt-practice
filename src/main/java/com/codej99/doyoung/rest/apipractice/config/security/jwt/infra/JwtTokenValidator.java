package com.codej99.doyoung.rest.apipractice.config.security.jwt.infra;

import com.codej99.doyoung.rest.apipractice.advice.exception.common.CUserSingoutException;
import com.codej99.doyoung.rest.apipractice.advice.exception.jwt.AccessTokenExpiredJwtException;
import com.codej99.doyoung.rest.apipractice.advice.exception.jwt.JwtRuntimeException;
import com.codej99.doyoung.rest.apipractice.advice.exception.jwt.NotExpiredJwtException;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model.JwtTokenUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import static com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model.JwtConfigConstants.REDIS_SIGNOUT_PREFIX;

@RequiredArgsConstructor
@Component
@Log
public class JwtTokenValidator {

    private final StringRedisTemplate redisTemplate;

    // accessTokenClaims 로 refresh token 을 추출 한다음에 refreshToken 유효기간을 체크해준다.
    public void validateToken(final String token) {
        // Expired 된 access token 의 Claims 가져오기
        try {
            // 유효기간이 지난 token 은 ExpiredJwtException 발생 !
            JwtTokenUtil.getClaimsJws(token);
        } catch (final Exception e) {
            log.info("JWT 검증 중, 알 수 없는 오류 발생");
            log.info(e.getMessage());
            throw new JwtRuntimeException("JWT 검증 중, 알 수 없는 오류 발생 {}", e);
        }
    }

    public void validateExpiredTokens(final String... tokens) {
        for (final String token : tokens) {
            validateExpiredToken(token);
        }
    }

    // expiredToken 의 claims 반환
    public Claims validateExpiredToken(final String token) {

        log.info("validateExpiredToken");

        Claims claims = null;

        try {
            JwtTokenUtil.getClaimsJws(token);
        } catch (final ExpiredJwtException eje) {
            // 이곳으로 와야만 함 !!
            claims = eje.getClaims();
            log.info("expired check token ::" + token);
        } catch (final Exception e) {
            log.info("JWT 검증 중, 알 수 없는 오류 발생");
            log.info(e.getMessage());
            throw new JwtRuntimeException("JWT 검증 중, 알 수 없는 오류 발생 {}", e);
        }

        if (claims == null) {
            throw new NotExpiredJwtException("유효기간이 지나지 않은 토큰 ! token ::: " + token);
        }

        return claims;
    }




}
