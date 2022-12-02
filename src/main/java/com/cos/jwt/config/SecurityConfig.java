package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthoriaztionFilter;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //ctrl + o로 override
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.addFilter(corsConfig.corsFilter());

        //csrf 안쓰겠다
        http.csrf().disable();
        //session 안쓰겠다 (stateless)
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 쓰디 않겠다
        .and()
        .addFilter(corsFilter)  // 인증(로그인)이 필요없을때는 @CrossOrigin 사용, 인증(로그인)이 필요있을때는 시큐리티 필터에 등록 인증
        .formLogin().disable()  // form 태그로 로그인 하는건 안한다
        .httpBasic().disable()
        .addFilter(new JwtAuthenticationFilter(authenticationManager()))  // AuthenticationManager를 던져줘야함 (필터가 manager를 통해서 로그인을 진행함)
        .addFilter(new JwtAuthoriaztionFilter(authenticationManager(), userRepository))
        .authorizeRequests()
        .antMatchers("/api/v1/user/**")
        .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
        .antMatchers("/api/v1/manager/**")
        .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
        .antMatchers("/api/v1/admin/**")
        .access("hasRole('ROLE_ADMIN')")
        .anyRequest().permitAll();
    }
}


