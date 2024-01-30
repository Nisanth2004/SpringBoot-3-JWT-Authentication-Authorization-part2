package com.newspring.JwtAmingosCode.auth;

import com.newspring.JwtAmingosCode.config.JwtService;
import com.newspring.JwtAmingosCode.token.Token;
import com.newspring.JwtAmingosCode.token.TokenRepository;
import com.newspring.JwtAmingosCode.token.TokenType;
import com.newspring.JwtAmingosCode.user.Role;
import com.newspring.JwtAmingosCode.user.User;
import com.newspring.JwtAmingosCode.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService
{
    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest request)
    {
        var user= User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
       var savedUser= repository.save(user);

        var jwtToken=jwtService.generateToken(user);
        // 2.logout

        // save the token in register level
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }

    // 2.logout
   private void revokeAllUserTokens(User user)
   {
       var validUserTokens=tokenRepository.findAllValidTokensByUser(user.getId());
       if(validUserTokens.isEmpty())
         return;
           validUserTokens.forEach(t->{
               t.setExpired(true);
               t.setRevoked(true);
           });

           // save the valid tokens
           tokenRepository.saveAll(validUserTokens);

   }
    private void saveUserToken(User user, String jwtToken) {
        var token= Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();
        // save the token in register level
        tokenRepository.save(token);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request)
    {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        // when the user is authenticated it will generate the token so we will store thst token
        var user=repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken=jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user,jwtToken);

        return AuthenticationResponse.builder().token(jwtToken).build();
    }
}
