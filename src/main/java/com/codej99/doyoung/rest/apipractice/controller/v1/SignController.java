package com.codej99.doyoung.rest.apipractice.controller.v1;


import com.codej99.doyoung.rest.apipractice.advice.exception.CEmailSigninFailedException;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.JwtResponseDto;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.JwtTokenProvider;
import com.codej99.doyoung.rest.apipractice.entity.User;
import com.codej99.doyoung.rest.apipractice.model.response.CommonResult;
import com.codej99.doyoung.rest.apipractice.model.response.SingleResult;
import com.codej99.doyoung.rest.apipractice.repo.UserJpaRepo;
import com.codej99.doyoung.rest.apipractice.service.ResponseService;
import io.jsonwebtoken.ExpiredJwtException;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Api(tags = {"1. Sign"})
@RequiredArgsConstructor
@RestController
@RequestMapping(value = "/v1")
@Log
public class SignController {

    private final UserJpaRepo userJpaRepo;
    private final JwtTokenProvider jwtTokenProvider;
    private final ResponseService responseService;
    private final PasswordEncoder passwordEncoder;
    private final RedisTemplate redisTemplate;

    @ApiOperation(value = "가입", notes = "회원가입을 한다.")
    @PostMapping(value = "/signup")
    public CommonResult signin(@ApiParam(value = "회원ID : 이메일", required = true) @RequestParam String id,
                               @ApiParam(value = "비밀번호", required = true) @RequestParam String password,
                               @ApiParam(value = "이름", required = true) @RequestParam String name) {

        userJpaRepo.save(User.builder()
                .uid(id)
                .password(passwordEncoder.encode(password))
                .name(name)
                .roles(Collections.singletonList("ROLE_USER"))
                .build());
        return responseService.getSuccessResult();
    }

    @ApiOperation(value = "로그인", notes = "이메일 회원 로그인을 한다.")
    @PostMapping(value = "/signin")
    public SingleResult<JwtResponseDto> signin(@ApiParam(value = "회원ID : 이메일", required = true) @RequestParam String id,
                                               @ApiParam(value = "비밀번호", required = true) @RequestParam String password) {
        User user = userJpaRepo.findByUid(id).orElseThrow(CEmailSigninFailedException::new);
        if (!passwordEncoder.matches(password, user.getPassword()))
            throw new CEmailSigninFailedException();

        return responseService.getSingleResult(jwtTokenProvider.save(user));
    }
//
//    @ApiOperation(value = "JWT 토큰 갱신", notes = "이메일 회원 아이디로 JWT 토큰 갱신을 한다.")
//    @PostMapping(path = "/signin/refresh")
//    public SingleResult<String> requestForNewAccessToken(
//            @ApiParam(value = "회원ID : 이메일", required = true) @RequestParam final String id
//    ) {
//
//        // TODO 쿠키 제거나 로그아웃 등으로 refresh token 이 로컬에 없는데 있다고 착각하고 요청을 보내면 없다고 알려준다.
//        // TODO refresh token 이 정상적으로 왔으면 client 가 함께 보낸 expired 된 access token 에서 username 을 꺼낸다.
//        // TODO redis에 username 을 key 로 저장해뒀던 refresh token 을 꺼내서 비교해본다.
//        // TODO expired 되지는 않았는지 확인한다.
//        // TODO 위의 조건이 맞으면 User DB에 접근하는 loadUserByUsername 메소드를 이용해서 다시 access token 을 만들어준다.
//
//        // ㅅ
//
//
//
//        String accessToken = null;
//        String refreshToken = null;
//        String refreshTokenFromDb = null;
//        String username = null;
//        Map<String, Object> map = new HashMap<>();
//        try {
//            accessToken = m.get("accessToken");
//            refreshToken = m.get("refreshToken");
//            log.info("access token in rnat: " + accessToken);
//            try {
//                username = jwtTokenProvider.getUserPk(accessToken);
//            } catch (IllegalArgumentException e) {
//
//            } catch (ExpiredJwtException e) { //expire됐을 때
//                username = e.getClaims().getSubject();
//                log.info("username from expired access token: " + username);
//            }
//
//            if (refreshToken != null) { //refresh를 같이 보냈으면.
//                try {
//                    ValueOperations<String, Object> vop = redisTemplate.opsForValue();
//                    String result = (String) vop.get(username);
//                    refreshTokenFromDb = result.getRefreshToken();
//                    log.info("rtfrom db: " + refreshTokenFromDb);
//                } catch (IllegalArgumentException e) {
//                    log.info("illegal argument!!");
//                }
//                //둘이 일치하고 만료도 안됐으면 재발급 해주기.
//                if (refreshToken.equals(refreshTokenFromDb) && !jwtTokenUtil.isTokenExpired(refreshToken)) {
//                    final UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//                    String newtok = jwtTokenUtil.generateAccessToken(userDetails);
//                    map.put("success", true);
//                    map.put("accessToken", newtok);
//                } else {
//                    map.put("success", false);
//                    map.put("msg", "refresh token is expired.");
//                }
//            } else { //refresh token이 없으면
//                map.put("success", false);
//                map.put("msg", "your refresh token does not exist.");
//            }
//
//        } catch (Exception e) {
//            throw e;
//        }
//        log.info("m: " + m);
//
//        return null;
//    }


    @EventListener(ApplicationReadyEvent.class)
    public void init() {
        log.info("[ApplicationReadyEvent] User create asdf");
        userJpaRepo.save(User.builder()
                .uid("asdf")
                .password(passwordEncoder.encode("asdf"))
                .name("name")
                .roles(Collections.singletonList("ROLE_USER"))
                .build());
    }
}