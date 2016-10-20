package com.smarth2o.twitter;

import com.github.scribejava.core.builder.ServiceBuilder;

import java.net.URLEncoder;

import com.github.scribejava.apis.TwitterApi.Authenticate;
import com.github.scribejava.core.model.OAuthConstants;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Token;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.model.Verifier;
import com.github.scribejava.core.oauth.OAuthService;

public class Helper {

    private static final String PROTECTED_UPDATE_POST_URL = "https://api.twitter.com/1.1/statuses/update.json?status=";
    private static final String PROTECTED_RESOURCE_URL = "https://api.twitter.com/1.1/account/verify_credentials.json";
    private static final String ENCODING = "UTF-8";
    private String consumerKey;
    private String consumerSecret;
    private String callbackURL;
    
    public Helper(String consumerKey, String consumerSecret, String callbackURL) {
        this.consumerKey = consumerKey;
        this.consumerSecret = consumerSecret;
        this.callbackURL = callbackURL;
    }

    public String redirectToAuthentication() throws Exception {
        OAuthService service = createService()
                .callback(callbackURL)
                .build();
	
        Token requestToken = service.getRequestToken();
	
        return service.getAuthorizationUrl(requestToken);
    }

    public Token redirectToApp(String oauthToken, String oauthVerifier) throws Exception {
        OAuthService service = createService().build();
        Token requestToken = new Token(oauthToken, oauthVerifier);
        Verifier verifier = new Verifier(oauthVerifier);
	
        Token accessToken = service.getAccessToken(requestToken, verifier);
	
        OAuthRequest request = new OAuthRequest(Verb.GET, PROTECTED_RESOURCE_URL, service);
        service.signRequest(accessToken, request);
        request.send();
	
        return accessToken;

    }

    public int tweet(Token accessToken, String status) throws Exception {
        OAuthService service = createService().build();
	
        String urlEncoded = URLEncoder.encode(status, ENCODING);
        OAuthRequest request = new OAuthRequest(Verb.POST, PROTECTED_UPDATE_POST_URL + urlEncoded, service);
	
        request.addOAuthParameter(OAuthConstants.TOKEN, accessToken.getToken());
        request.addOAuthParameter(OAuthConstants.TOKEN_SECRET, accessToken.getSecret());
        service.signRequest(accessToken, request);
	
        return request.send().getCode();
    }

    private ServiceBuilder createService() {
        return new ServiceBuilder()
                .provider(Authenticate.class)
                .apiKey(consumerKey)
                .apiSecret(consumerSecret);
    }

}