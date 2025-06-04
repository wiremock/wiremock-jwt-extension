package org.wiremock.extension.jwt;

import com.github.jknack.handlebars.Helper;
import com.github.tomakehurst.wiremock.extension.TemplateHelperProviderExtension;
import java.util.Map;

public class JwtHelpersExtension implements TemplateHelperProviderExtension {

    private final JwtSigningKeySettings jwtSigningKeySettings;

    public JwtHelpersExtension(JwtSigningKeySettings jwtSigningKeySettings) {
        this.jwtSigningKeySettings = jwtSigningKeySettings;
    }

    @Override
    public Map<String, Helper<?>> provideTemplateHelpers() {
        JwtHandlebarsHelper jwtHandlebarsHelper = new JwtHandlebarsHelper(jwtSigningKeySettings);
        JwksHandlebarsHelper jwksHandlebarsHelper = new JwksHandlebarsHelper(jwtSigningKeySettings);
        return Map.of(
                "jwt", jwtHandlebarsHelper,
                "claims", new ClaimListHandlebarsHelper(),
                "claimsObject", new ClaimsObjectHandlebarsHelper(),
                "jwks", jwksHandlebarsHelper);
    }

    @Override
    public String getName() {
        return "jwt-template-helpers";
    }
}
