package com.cos.jwt.config.auth;

        import org.springframework.security.core.userdetails.UserDetails;
        import org.springframework.security.core.userdetails.UserDetailsService;
        import org.springframework.security.core.userdetails.UsernameNotFoundException;
        import org.springframework.stereotype.Service;

        import com.cos.jwt.model.User;
        import com.cos.jwt.repository.UserRepository;

        import lombok.RequiredArgsConstructor;

//http://localhost:8086/login 일때 동작함(스프링 시큐리티의 정책상)
//근데 동작을 안함 (formLogin을 막아놨기 떄문)
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService{

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService : 진입");
        User user = userRepository.findByUsername(username);

        // session.setAttribute("loginUser", user);
        return new PrincipalDetails(user);
    }
}