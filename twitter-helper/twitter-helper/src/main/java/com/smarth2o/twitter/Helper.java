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

    public String redirectToAuthentication() {
    	try {
	        OAuthService service = createService()
	                .callback(callbackURL)
	                .build();
	
	        Token requestToken = service.getRequestToken();
	
	        return service.getAuthorizationUrl(requestToken);
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    	return null;
    }

    public Token redirectToApp(String oauthToken, String oauthVerifier) {
    	try {
	        OAuthService service = createService().build();
	        Token requestToken = new Token(oauthToken, oauthVerifier);
	        Verifier verifier = new Verifier(oauthVerifier);
	
	        Token accessToken = service.getAccessToken(requestToken, verifier);
	
	        OAuthRequest request = new OAuthRequest(Verb.GET, PROTECTED_RESOURCE_URL, service);
	        service.signRequest(accessToken, request);
	        request.send();
	
	        return accessToken;
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    	return null;
    }

    public int tweet(Token accessToken, String status) {
    	try {
	        OAuthService service = createService().build();
	
	        String urlEncoded = URLEncoder.encode(status, ENCODING);
	        OAuthRequest request = new OAuthRequest(Verb.POST, PROTECTED_UPDATE_POST_URL + urlEncoded, service);
	
	        request.addOAuthParameter(OAuthConstants.TOKEN, accessToken.getToken());
	        request.addOAuthParameter(OAuthConstants.TOKEN_SECRET, accessToken.getSecret());
	        service.signRequest(accessToken, request);
	
	        return request.send().getCode();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return -1;
    }

    private ServiceBuilder createService() {
        return new ServiceBuilder()
                .provider(Authenticate.class)
                .apiKey(consumerKey)
                .apiSecret(consumerSecret);
    }

}