package com.esso.booknetwork.auth;

import com.esso.booknetwork.email.EmailService;
import com.esso.booknetwork.email.EmailTemplateName;
import com.esso.booknetwork.models.Token;
import com.esso.booknetwork.models.User;
import com.esso.booknetwork.repository.RoleRepository;
import com.esso.booknetwork.repository.TokenRepository;
import com.esso.booknetwork.repository.UserRepository;
import com.esso.booknetwork.security.JwtService;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final EmailService emailService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    @Value("${application.mailing.frontend.activation-url}")
    private String activationUrl;

    public void register(RegistrationRequest request) throws MessagingException {
       var userRole =  roleRepository.findByName("USER")
               .orElseThrow(() -> new IllegalStateException("ROLE USER was not initialized"));
       var user = User.builder()
               .firstname(request.getFirstname())
               .lastname(request.getLastname())
               .email(request.getEmail())
               .password(passwordEncoder.encode(request.getPassword()))
               .accountLocked(false)
               .enabled(true)
               .roles(List.of(userRole))
               .build();
       userRepository.save(user);
       sendValidationEmail(user);
    }

    private void sendValidationEmail(User user) throws MessagingException {
        var newToken = generateAndSaveActivationToken(user);

        emailService.sendEmail(
                user.getEmail(),
                user.fullName(),
                EmailTemplateName.ACTIVATE_ACCOUNT,
                activationUrl,
                (String) newToken,
                "Account activation"
        );
    }

    private Object generateAndSaveActivationToken(User user) {
        String generatedToken = generateActivationCode(6);
        var token = Token.builder()
                .token(generatedToken)
                .createdAt(LocalDateTime.now())
                .expiredAt(LocalDateTime.now().plusMinutes(15))
                .user(user)
                .build();
        tokenRepository.save(token);
        return generatedToken;
    }

    private String generateActivationCode(int length) {
        String characters = "0123456789";
        StringBuilder codeBuilder = new StringBuilder();
        SecureRandom secureRandom = new SecureRandom();
        for(int i = 0; i < length; i++){
            int randomIndex = secureRandom.nextInt(characters.length());
            codeBuilder.append(characters.charAt(randomIndex));
        }
       return codeBuilder.toString();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        var auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var claims = new HashMap<String, Object>();
        var user = ((User)auth.getPrincipal());
        claims.put("fullName",user.fullName());
        var jwtToken = jwtService.generateToken(claims, user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
    //@Transactional
    public void activateAccount(String token) throws MessagingException {
       Token saveToken = tokenRepository.findByToken(token)
               .orElseThrow(()-> new RuntimeException("Invalid token"));
       if(LocalDateTime.now().isAfter(saveToken.getExpiredAt())){
           sendValidationEmail(saveToken.getUser());
           throw new RuntimeException("Activation token has expired. A new token has been sent to the same email address");
       }
       var user = userRepository.findById(saveToken.getUser().getId())
               .orElseThrow(()-> new UsernameNotFoundException("User not found"));
       user.setEnabled(true);
       userRepository.save(user);
       saveToken.setValidatedAt(LocalDateTime.now());
       tokenRepository.save(saveToken);
    }
}
