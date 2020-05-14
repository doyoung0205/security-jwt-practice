package com.codej99.doyoung.rest.apipractice.config.security.jwt;

import com.codej99.doyoung.rest.apipractice.advice.exception.common.CUserSingoutException;
import com.codej99.doyoung.rest.apipractice.advice.exception.jwt.AccessTokenExpiredJwtException;
import com.codej99.doyoung.rest.apipractice.advice.exception.jwt.JwtRuntimeException;
import com.codej99.doyoung.rest.apipractice.advice.exception.jwt.NotExpiredJwtException;
import com.codej99.doyoung.rest.apipractice.advice.exception.jwt.RefreshTokenExpiredJwtException;
import com.codej99.doyoung.rest.apipractice.entity.User;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@RequiredArgsConstructor
@Component
@Log
public class JwtTokenProvider {

//    public static final String CLAIMS_USER_KEY = "user";

    @Value("spring.jwt.secret")
    private String secretKey;

    final private static int REFRESH_TOKEN_VALIDITY = 0;
    final private static int ACCESS_TOKEN_VALIDITY = 0;
    final private static String REDIS_SIGNOUT_PREFIX = "SIGN_OUT_";

    private final String ACCESS_TOKEN_KEY = "X-AUTH-TOKEN";
    private final String REFRESH_TOKEN_KEY = "REFRESH-X-AUTH-TOKEN";

    private final UserDetailsService userDetailsService;
    private final StringRedisTemplate redisTemplate;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }


    //Jwt 토큰 생성 with User and now
    public String createToken(User user, LocalDateTime now, LocalDateTime expiresAt) {

        Claims claims = createClaims(user);

        return Jwts.builder()
                .setClaims(claims) // 데이터
                .setIssuedAt(Date.from(now.atZone(ZoneId.systemDefault()).toInstant())) // 토큰 발행 일자
                .setExpiration(Date.from(expiresAt.atZone(ZoneId.systemDefault()).toInstant())) // set Expire Time
                .signWith(SignatureAlgorithm.HS256, secretKey) // 암호화 알고리즘, secret 값 세팅
                .compact();
    }

    //Jwt 토큰 생성 with User and now
    public String createToken(final User user) {

        final LocalDateTime now = LocalDateTime.now();
        final LocalDateTime expiresAt = getAccessTokenExpiresAt(now);

        Claims claims = createClaims(user);

        return Jwts.builder()
                .setClaims(claims) // 데이터
                .setIssuedAt(Date.from(now.atZone(ZoneId.systemDefault()).toInstant())) // 토큰 발행 일자
                .setExpiration(Date.from(expiresAt.atZone(ZoneId.systemDefault()).toInstant())) // set Expire Time
                .signWith(SignatureAlgorithm.HS256, secretKey) // 암호화 알고리즘, secret 값 세팅
                .compact();
    }

    private Claims createClaims(User user) {
        Claims claims = Jwts.claims().setSubject(user.getUid());

        claims.put("msrl", user.getMsrl());
        claims.put("password", user.getPassword());
        claims.put("roles", user.getRoles());
        claims.put("name", user.getName());
        return claims;
    }

    // Jwt 토큰 생성 with User return JwtResponseDto
    public JwtResponseDto save(User user) {

        final LocalDateTime now = LocalDateTime.now();
        final LocalDateTime accessTokenExpiresAt = getAccessTokenExpiresAt(now);
        final LocalDateTime refreshTokenExpiresAt = getRefreshTokenExpiresAt(now);

        // CREATE ACCESS_TOOKEN
        final String accessToken = createToken(user, now, accessTokenExpiresAt);

        // CREATE REFRESH_TOKEN
        final String refreshToken = createToken(user, now, refreshTokenExpiresAt);

        //  refreshToken redis 에 저장
        final ValueOperations<String, String> values = redisTemplate.opsForValue();

        /**
         * @Key : username
         * @Value : refreshToken
         * */
        // TODO accessToken 에다가 Barer prefix 붙이기
        // private final static String JWT_PREFIX = "BARER ";
        values.set(user.getUid(), refreshToken);

        //  CREATE JwtResponseDto
        return JwtResponseDto.builder()
                .user(user)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private LocalDateTime getRefreshTokenExpiresAt(LocalDateTime now) {
        return now.plusWeeks(REFRESH_TOKEN_VALIDITY);
    }

    private LocalDateTime getAccessTokenExpiresAt(LocalDateTime now) {
        return now.plusMinutes(ACCESS_TOKEN_VALIDITY);
    }

    // Access Token 유효성 검사
    public boolean validateAccessToken(final String accessToken) {

        if (StringUtils.isEmpty(accessToken)) return false;

        try {

            // 유효기간이 지난 accessToken 은 ExpiredJwtException 발생 !
            validateToken(accessToken);

            //  Logout BlackList 에 있는지 확인
            validateLogoutAccessToken(accessToken);

            return true;
        } catch (final ExpiredJwtException accessTokenClaims) {

            final String accessTokenSubject = accessTokenClaims.getClaims().getSubject();

            getRefreshTokenByRedis(accessTokenSubject);

            throw new AccessTokenExpiredJwtException("Access Token JWT 유효기간 초과");

        }
    }


    // Redis 에서 uid 가지고 refresh 가져옴
    private String getRefreshTokenByRedis(final String uid) {

        // Refresh Token  가져오기
        final String refreshTokenByRedis = redisTemplate.opsForValue().get(uid);

        // Token 자체의 유효성 검사
        validateToken(refreshTokenByRedis);

        return refreshTokenByRedis;
    }


    public void validateUpdateAccessToken(final String accessToken, final String refreshToken, final String id) {

        // accessToken refreshToken expired validation
//        validateExpiredTokens(accessToken, refreshToken);

        // expired 된 accessToken 에서 userId 가져오기
        final String accessSubject = getSubjectByExpiredToken(accessToken);

        // refreshToken 에서 userId 가져오기
        final String refreshSubject = getSubjectByExpiredToken(refreshToken);

        if (!accessSubject.equals(refreshSubject)) {
            // accessSubject와 refreshSubject 가 같지 않음 ERROR
            log.info("accessSubject와 refreshSubject 가 같지 않습니다.");
            throw new MalformedJwtException("accessSubject와 refreshSubject 가 같지 않습니다.");
        }

        if (!accessSubject.equals(id)) {
            // accessSubject와 userid 가 같지 않음 ERROR
            log.info("accessSubject와 id 가 같지 않습니다.");
            throw new MalformedJwtException("accessSubject와 id 가 같지 않습니다.");
        }

        //  redis에 username 을 key 로 저장해뒀던 refresh token 가져오기
        final String refreshSubjectByRedis = getRefreshTokenByRedis(accessSubject);

        if (!refreshSubject.equals(refreshSubjectByRedis)) {
            // refreshSubject refreshSubjectByRedis 가 같지 않음 ERROR
            log.info("refreshSubject 와 refreshSubjectByRedis 가 같지 않습니다.");
            throw new MalformedJwtException("refreshSubject 와 refreshSubjectByRedis 가 같지 않습니다.");
        }

    }

    private void validateExpiredTokens(final String... tokens) {
        for (final String token : tokens) {
            validateExpiredToken(token);
        }
    }

    private void validateExpiredToken(final String token) {

        try {
            validateToken(token);
        } catch (final ExpiredJwtException eje) {
            // 이곳으로 와야만 함 !!
            log.info("expired check token ::" + token);
        } catch (final Exception e) {
            log.info("JWT 검증 중, 알 수 없는 오류 발생");
            throw new JwtRuntimeException("JWT 검증 중, 알 수 없는 오류 발생 {}", e);
        }

        throw new NotExpiredJwtException("유효기간이 지나지 않은 토큰 ! token ::: " + token);
    }


    public String updateAccessToken(final String accessToken) {
        //  access token 기간을 늘려준다.

        final LocalDateTime now = LocalDateTime.now();
        final LocalDateTime expiresAt = getAccessTokenExpiresAt(now);
        final String accessSubject = getSubjectByExpiredToken(accessToken);

        Claims claims = Jwts.claims().setSubject(accessSubject);

        return Jwts.builder().setClaims(claims)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .setExpiration(Date.from(expiresAt.atZone(ZoneId.systemDefault()).toInstant()))
                .compact();
    }


    private String getSubjectByExpiredToken(String token) {

        // Expired 된 토큰 인 지 확인
        validateExpiredToken(token);

        return getSubjectByToken(token);
    }


    // accessTokenClaims 로 refresh token 을 추출 한다음에 refreshToken 유효기간을 체크해준다.
    private void validateToken(final String token) {
        // Expired 된 access token 의 Claims 가져오기
        try {
            // 유효기간이 지난 token 은 ExpiredJwtException 발생 !
            getClaimsJws(token);
        } catch (final ExpiredJwtException refreshTokenClaims) {
            throw new RefreshTokenExpiredJwtException("Refresh Token JWT 유효기간 초과");
        } catch (final Exception e) {
            log.info("JWT 검증 중, 알 수 없는 오류 발생");
            throw new JwtRuntimeException("JWT 검증 중, 알 수 없는 오류 발생 {}", e);
        }
    }


    //DB NO 접근
    public Authentication getAuthentication(String token) {

        final User user = getUserParseToken(token);

        //  =============== 로그 확인 =============
        log.info("============== JwtTokenProvider.getAuthentication ==============");
        log.info("user ::: " + user);
        log.info("==================================================================");

        assert user != null : "user must not be blank";

        return new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());
    }


    private String getSubjectByToken(String token) {
        return getClaimsJws(token).getBody().getSubject();
    }

    private Claims getClaimsByToken(String token) {
        return getClaimsJws(token).getBody();
    }

    private Jws<Claims> getClaimsJws(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
    }


    private User getUserParseToken(final String token) {

        final Claims claims = getClaimsByToken(token);
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

    // Request 의 Header 에서 token 파싱 : "X-AUTH-TOKEN: jwt 토큰"
    public String resolveAccessToken(HttpServletRequest req) {
        return req.getHeader(ACCESS_TOKEN_KEY);
    }

    public String resolveRefreshToken(HttpServletRequest req) {
        return req.getHeader(REFRESH_TOKEN_KEY);
    }

    private void validateLogoutAccessToken(final String accessToken) {
        if (null != redisTemplate.opsForValue().get(REDIS_SIGNOUT_PREFIX + accessToken)) {
            throw new CUserSingoutException("이미 로그아웃을 한 유저입니다.");
        }
    }
}


/*
 *  Jwt 토큰 생성 및 유효성 검증을 하는 컴포넌트 입니다. Jwt 는 여러가지 암호화 알고리즘을 제공하며 알고리즘 (SignatureAlgorithm.XXX)과 비밀키(secretKey)를 가지고 토큰을 생성하게 됩니다.
 *  이때 claim 정보에는 토큰에 부가적으로 실어 보낼 정보를 세팅할 수 있습니다.
 *  claim 정보에 회원을 구분할 수 있는 값을 세팅하였다가 토큰이 들어오면 해당 값으로 회원을 구분하여 리소스를 제공하면 됩니다. 그리고 Jwt 토큰에는 expire 시간을 세팅할 수 있습니다.
 *  토큰 발급 후 일정 시간 이후에는 토큰을 만료시키는 데 사용할 수 있습니다.
 *  resolveToken 메서드는 Http request header 에 세팅된 토큰 값을 가져와 유효성을 체크합니다.
 *  제한된 리소스를 요청할 때 Http header 에 토큰을 세팅하여 호출하면 유효성을 검증하여 사용자 인증을 할 수 있습니다.
 * */
