package org.wiremock.extension.jwt;

import com.github.jknack.handlebars.Options;
import com.github.tomakehurst.wiremock.extension.responsetemplating.helpers.HandlebarsHelper;
import java.io.IOException;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.lang.JoseException;

public class JwksHandlebarsHelper extends HandlebarsHelper<Object> {

    private final JwtSigningKeySettings jwtSigningKeySettings;

    public JwksHandlebarsHelper(JwtSigningKeySettings jwtSigningKeySettings) {
        this.jwtSigningKeySettings = jwtSigningKeySettings;
    }

    @Override
    public Object apply(Object context, Options options) throws IOException {
        try {
            JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(jwtSigningKeySettings.getKeyPair().publicKey);
            jsonWebKey.setAlgorithm("RS256");
            jsonWebKey.setUse("sig");
            jsonWebKey.setKeyId(jwtSigningKeySettings.getRs256PublicKeyId());
            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(jsonWebKey);
            return jsonWebKeySet.toJson();
        } catch (JoseException e) {
            throw new IOException(e);
        }
    }

}
