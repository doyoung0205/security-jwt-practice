package com.codej99.doyoung.rest.apipractice.controller.v1;


import com.codej99.doyoung.rest.apipractice.advice.exception.common.CEmailSigninFailedException;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.JwtResponseDto;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.JwtTokenProvider;
import com.codej99.doyoung.rest.apipractice.entity.User;
import com.codej99.doyoung.rest.apipractice.model.response.CommonResult;
import com.codej99.doyoung.rest.apipractice.model.response.SingleResult;
import com.codej99.doyoung.rest.apipractice.repo.UserJpaRepo;
import com.codej99.doyoung.rest.apipractice.service.ResponseService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;

import static com.codej99.doyoung.rest.apipractice.config.security.jwt.SecurityConstants.ROLE_USER;

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

    @ApiOperation(value = "가입", notes = "회원가입을 한다.")
    @PostMapping(value = "/signup")
    public CommonResult signin(@ApiParam(value = "회원ID : 이메일", required = true) @RequestParam final String id,
                               @ApiParam(value = "비밀번호", required = true) @RequestParam final String password,
                               @ApiParam(value = "이름", required = true) @RequestParam final String name) {


        userJpaRepo.save(User.builder()
                .uid(id)
                .password(passwordEncoder.encode(password))
                .name(name)
                .roles(Collections.singletonList(ROLE_USER))
                .build());

        return responseService.getSuccessResult();
    }

    @ApiOperation(value = "로그인", notes = "이메일 회원 로그인을 한다.")
    @PostMapping(value = "/signin")
    public SingleResult<JwtResponseDto> signin(@ApiParam(value = "회원ID : 이메일", required = true) @RequestParam final String id,
                                               @ApiParam(value = "비밀번호", required = true) @RequestParam final String password) {

        final User user = userJpaRepo.findByUid(id).orElseThrow(CEmailSigninFailedException::new);
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new CEmailSigninFailedException();
        }
        return responseService.getSingleResult(jwtTokenProvider.save(user));
    }

    @ApiOperation(value = "JWT ACCESS TOKEN 갱신", notes = "이메일 회원 아이디로 JWT 토큰 갱신을 한다.")
    @PostMapping(path = "/signin/refresh")
    public SingleResult<JwtResponseDto> requestForNewAccessToken(
            HttpServletRequest request,
            @ApiParam(value = "회원ID : 이메일", required = true) @RequestParam final String id
    ) {
        // parameter check
        final String accessToken = jwtTokenProvider.resolveAccessToken(request);
        assert accessToken != null : "accessToken must not be blank";

        final String refreshToken = jwtTokenProvider.resolveRefreshToken(request);
        assert refreshToken != null : "refreshToken must not be blank";

        // accessToken, refreshToken validation
        jwtTokenProvider.validateUpdateAccessToken(accessToken, refreshToken, id);

        // create new accessToken
        responseService.getSingleResult(jwtTokenProvider.updateAccessToken(accessToken));
        return null;
    }


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