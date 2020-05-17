package com.codej99.doyoung.rest.apipractice.config.security.jwt.application;

import com.codej99.doyoung.rest.apipractice.advice.exception.common.CUserSingoutException;
import com.codej99.doyoung.rest.apipractice.advice.exception.jwt.AccessTokenExpiredJwtException;
import com.codej99.doyoung.rest.apipractice.advice.exception.jwt.NotFoundRefreshTokenInRedis;
import com.codej99.doyoung.rest.apipractice.advice.exception.jwt.RefreshTokenExpiredJwtException;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.JwtTokenRepository;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.JwtTokenValidator;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model.JwtResponseDto;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model.JwtTokenUtil;
import com.codej99.doyoung.rest.apipractice.entity.User;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import static com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model.JwtConfigConstants.JWT_SECRET_KEY;
import static com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model.JwtConfigConstants.REDIS_SIGNOUT_PREFIX;


@RequiredArgsConstructor
@Component
@Log
@Service
public class JwtTokenServiceImpl implements JwtTokenService {

    private final StringRedisTemplate redisTemplate;
    private final JwtTokenRepository jwtTokenRepository;
    private final JwtTokenValidator jwtTokenValidator;

    // Jwt 토큰 생성 with User return JwtResponseDto
    public JwtResponseDto initialize(final User user) {

        final LocalDateTime now = LocalDateTime.now();
        final LocalDateTime accessTokenExpiresAt = JwtTokenUtil.getAccessTokenExpiresAt(now);
        final LocalDateTime refreshTokenExpiresAt = JwtTokenUtil.getRefreshTokenExpiresAt(now);

        // CREATE ACCESS_TOOKEN
        final String accessToken = JwtTokenUtil.createToken(user, now, accessTokenExpiresAt);

        // CREATE REFRESH_TOKEN
        final String refreshToken = JwtTokenUtil.createToken(user, now, refreshTokenExpiresAt);

        //  refreshToken redis 에 저장
        saveRefreshTokenToRedis(user.getUid(), refreshToken, refreshTokenExpiresAt);

        //  CREATE JwtResponseDto
        return JwtResponseDto.builder()
                .user(user)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }


    public void validateUpdateAccessToken(final String accessToken, final String refreshToken, final String id) {

        log.info("validateUpdateAccessToken");

        final String accessSubject = jwtTokenRepository.getSubjectByExpiredToken(accessToken);
        final String refreshSubject = jwtTokenRepository.getSubjectByExpiredToken(refreshToken);

        if (!accessSubject.equals(refreshSubject)) {
            throw new MalformedJwtException("accessSubject와 refreshSubject 가 같지 않습니다.");
        }

        if (!accessSubject.equals(id)) {
            throw new MalformedJwtException("accessSubject와 id 가 같지 않습니다.");
        }

        // redis에 username 을 key 로 저장해뒀던 refresh token 가져오기
        final String refreshSubjectByRedis = jwtTokenRepository.getRefreshTokenByRedis(accessSubject);

        if (!refreshToken.equals(refreshSubjectByRedis)) {
            throw new MalformedJwtException("refreshSubject 와 refreshSubjectByRedis 가 같지 않습니다.");
        }
    }

    // Access Token 유효성 검사
    public boolean validateAccessToken(final String accessToken) {

        log.info("validateAccessToken");

        if (StringUtils.isEmpty(accessToken)) return false;

        try {

            // 유효기간이 지난 accessToken 은 ExpiredJwtException 발생 !
            jwtTokenValidator.validateToken(accessToken);

            //  Logout BlackList 에 있는지 확인
            validateLogoutAccessToken(accessToken);

            return true;
        } catch (final ExpiredJwtException accessTokenClaims) {

            final String accessTokenSubject = accessTokenClaims.getClaims().getSubject();

            jwtTokenRepository.getRefreshTokenByRedis(accessTokenSubject);

            throw new AccessTokenExpiredJwtException("Access Token JWT 유효기간 초과");

        }
    }

    public boolean validateRefreshToken(final String refreshToken) {

        if (StringUtils.isEmpty(refreshToken)) return false;
        log.info("validateRefreshToken");

        try {

            // 유효기간이 지난 accessToken 은 ExpiredJwtException 발생 !
            jwtTokenValidator.validateToken(refreshToken);

            //  redis 에 있는지 확인
            validateRefreshTokenToRedis(refreshToken);

            return true;
        } catch (final ExpiredJwtException refreshTokenClaims) {

            final String accessTokenSubject = refreshTokenClaims.getClaims().getSubject();

            jwtTokenRepository.getRefreshTokenByRedis(accessTokenSubject);

            throw new RefreshTokenExpiredJwtException("Refresh Token JWT 유효기간 초과");

        }
    }

    private void validateRefreshTokenToRedis(final String refreshToken) {

        final String subject = JwtTokenUtil.getSubjectByToken(refreshToken);
        final String refreshTokenByRedis = redisTemplate.opsForValue().get(subject);

        if (StringUtils.isEmpty(refreshTokenByRedis)) {
            throw new NotFoundRefreshTokenInRedis("redis 에 refresh token 이 존재하지 않습니다.");
        }

        if (refreshTokenByRedis.equals(refreshToken)) {
            throw new NotFoundRefreshTokenInRedis("redis 에 refresh token 이 일치하지 않습니다.");
        }
    }


    //DB NO 접근
    public Authentication getAuthentication(final String token) {

        final User user = jwtTokenRepository.getUserByToken(token);

        //  =============== 로그 확인 =============
        log.info("============== JwtTokenProvider.getAuthentication ==============");
        log.info("user ::: " + user);
        log.info("==================================================================");

        assert user != null : "user must not be blank";

        return new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());
    }


    private void updateRefreshTokenToRedis(final String uid, final String refreshToken, final LocalDateTime refreshTokenExpiresAt) {

        final ValueOperations<String, String> values = redisTemplate.opsForValue();
        values.set(uid, refreshToken);

        // 리프레시 토큰과 같은 유효시간 설정하기
        redisTemplate.expireAt(uid, Date.from(refreshTokenExpiresAt.atZone(ZoneId.systemDefault()).toInstant()));
    }

    public String updateToken(final String token, final LocalDateTime expiresAt) {
        //  access token 기간을 늘려준다.

        log.info("updateAccessToken");

        final String accessSubject = jwtTokenRepository.getSubjectByExpiredToken(token);

        Claims claims = Jwts.claims().setSubject(accessSubject);

        return Jwts.builder().setClaims(claims)
                .signWith(SignatureAlgorithm.HS256, JWT_SECRET_KEY)
                .setExpiration(Date.from(expiresAt.atZone(ZoneId.systemDefault()).toInstant()))
                .compact();
    }

    /**
     * @param uid                   키
     * @param refreshToken          리프레시 토큰
     * @param refreshTokenExpiresAt 유효기간
     */
    private void saveRefreshTokenToRedis(final String uid, final String refreshToken, final LocalDateTime refreshTokenExpiresAt) {
        final ValueOperations<String, String> values = redisTemplate.opsForValue();
        values.set(uid, refreshToken);

        // 리프레시 토큰과 같은 유효시간 설정하기
        redisTemplate.expireAt(uid, Date.from(refreshTokenExpiresAt.atZone(ZoneId.systemDefault()).toInstant()));
    }

    public String updateRefreshToken(final String refreshToken) {
        log.info("updateAccessToken");

        validateRefreshToken(refreshToken);

        final LocalDateTime now = LocalDateTime.now();
        final LocalDateTime refreshTokenExpiresAt = JwtTokenUtil.getRefreshTokenExpiresAt(now);

        // Refresh Token 유효시간 갱신하기
        final String updateRefreshToken = updateToken(refreshToken, refreshTokenExpiresAt);

        final String subjectByToken = JwtTokenUtil.getSubjectByToken(updateRefreshToken);

        // Redis 에 있는 유효시간도 갱신하기
        updateRefreshTokenToRedis(subjectByToken, updateRefreshToken, refreshTokenExpiresAt);

        return updateRefreshToken;
    }


    private void validateLogoutAccessToken(final String accessToken) {
        if (null != redisTemplate.opsForValue().get(REDIS_SIGNOUT_PREFIX + accessToken)) {
            throw new CUserSingoutException("이미 로그아웃을 한 유저입니다.");
        }
    }

}




