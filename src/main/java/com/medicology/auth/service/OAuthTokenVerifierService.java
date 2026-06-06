package com.medicology.auth.service;

import com.medicology.auth.exception.ApiException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class OAuthTokenVerifierService {

    private static final Logger log = LoggerFactory.getLogger(OAuthTokenVerifierService.class);
    private static final String GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo";
    private static final String FACEBOOK_GRAPH_URL = "https://graph.facebook.com/me?fields=id,name,email";

    private final RestClient.Builder restClientBuilder;

    public record OAuthProfile(String providerId, String email, String name) {}

    public OAuthProfile verifyGoogleAccessToken(String accessToken) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> userInfo = restClientBuilder.build()
                    .get()
                    .uri(GOOGLE_USERINFO_URL)
                    .header("Authorization", "Bearer " + accessToken)
                    .retrieve()
                    .body(Map.class);

            if (userInfo == null) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "Không thể xác thực token Google.");
            }

            String id = (String) userInfo.get("id");
            String email = (String) userInfo.get("email");
            String name = (String) userInfo.get("name");

            if (id == null || email == null) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "Token Google không chứa thông tin cần thiết.");
            }

            return new OAuthProfile(id, email, name != null ? name : email);
        } catch (ApiException ex) {
            throw ex;
        } catch (Exception ex) {
            log.warn("google_token_verify_failed reason={}", ex.getMessage());
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Token Google không hợp lệ hoặc đã hết hạn.");
        }
    }

    public OAuthProfile verifyFacebookAccessToken(String accessToken) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> userInfo = restClientBuilder.build()
                    .get()
                    .uri(FACEBOOK_GRAPH_URL + "&access_token=" + accessToken)
                    .retrieve()
                    .body(Map.class);

            if (userInfo == null) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "Không thể xác thực token Facebook.");
            }

            String id = (String) userInfo.get("id");
            String email = (String) userInfo.get("email");
            String name = (String) userInfo.get("name");

            if (id == null || email == null) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "Token Facebook không chứa thông tin cần thiết.");
            }

            return new OAuthProfile(id, email, name != null ? name : email);
        } catch (ApiException ex) {
            throw ex;
        } catch (Exception ex) {
            log.warn("facebook_token_verify_failed reason={}", ex.getMessage());
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Token Facebook không hợp lệ hoặc đã hết hạn.");
        }
    }
}
