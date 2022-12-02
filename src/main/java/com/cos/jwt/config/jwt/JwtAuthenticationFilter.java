package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// /login이라고 요청해서 username, password를 post로 전송하면 이 필터가 동작함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도중");
        // 1. username, password 받아서 (getInputStream에 username과 password가 담겨있음)
        // 2. 정상인지 로그인 시도를 해본다 (authenticationManger로 로그인 시도를 하면 PrincipalDetailsService가 호출됨
        // 3. 그안에 loadUserByUsername이 실행 됨(로그인 처리)
        // 4. PrincipalDetails를 세션에 담고 (권한 관리를 위해서는 필요)
        // 5. JWT토큰을 만들어서 응답해주면 됨

        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println(input);
//            }
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 이게 실행될때 Principal의 loadUserByUsernam() 함수가 실행된 후 정상이면 Authentication이 리턴됨 / password는 알아서 스프링이 처리해줌
            // authentication은 로그인 정보가 들어가있음
            // 데이터데이스에 있는 username과 password가 일치한다(인증 완료)
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // principalDetails가 출력된다는것은 로그인이 잘되었다는 얘기
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨:" + principalDetails.getUser().getUsername());
            System.out.println("==================================");

            // 로그인이 저장되었으면 authentication 객체가 session영역에 저장을 해야하고, 그 방법이 return해주는 거임
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 거임
            // 굳이 jwt 토큰을 사용하면서 session을 만들 이유가 없음. 단지 권한처리때문에 session에 넣어준다
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 sucessfulAuthentication 함수가 실행된다
    // 여기서 JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        PrincipalDetails principalDetailis = (PrincipalDetails) authResult.getPrincipal();

        //RSA 방식(공개키, 개인키)은 아니고 Hash암호방식(secret키) -> Hash방식을 더 많이 씀
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))  // 만료시간
                .withClaim("id", principalDetailis.getUser().getId())
                .withClaim("username", principalDetailis.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);
    }
}
