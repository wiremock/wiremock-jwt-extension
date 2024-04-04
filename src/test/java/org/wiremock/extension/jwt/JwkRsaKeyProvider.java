package org.wiremock.extension.jwt;

import static com.github.tomakehurst.wiremock.common.Exceptions.uncheck;
import static com.github.tomakehurst.wiremock.http.RequestMethod.GET;

import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.github.tomakehurst.wiremock.common.Json;
import com.github.tomakehurst.wiremock.http.ImmutableRequest;
import com.github.tomakehurst.wiremock.http.Response;
import com.github.tomakehurst.wiremock.http.client.HttpClient;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class JwkRsaKeyProvider implements RSAKeyProvider {

    private final HttpClient client;
    private final String baseUrl;
    public JwkRsaKeyProvider(HttpClient client, String baseUrl) {
        this.client = client;
        this.baseUrl = baseUrl;
    }

    @Override
    public RSAPublicKey getPublicKeyById(String keyId) {
        final ImmutableRequest request = ImmutableRequest.create()
                .withAbsoluteUrl(baseUrl + "/.well-known/jwks.json")
                .withMethod(GET)
                .build();

        final Rsa256JsonWebKeySet keySet = uncheck(() -> {
            final Response response = client.execute(request);
            return Json.read(response.getBody(), Rsa256JsonWebKeySet.class);
        }, Rsa256JsonWebKeySet.class); 

        return keySet
                .getKey(keyId)
                .map(Rsa256JsonWebKey::getPublicKey)
                .orElseThrow(() -> new IllegalArgumentException("Key with ID " + keyId + " not found"));
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        return null;
    }

    @Override
    public String getPrivateKeyId() {
        return null;
    }
}
