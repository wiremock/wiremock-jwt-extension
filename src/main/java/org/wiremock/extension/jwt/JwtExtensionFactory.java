package org.wiremock.extension.jwt;

import com.github.tomakehurst.wiremock.core.Admin;
import com.github.tomakehurst.wiremock.extension.Extension;
import com.github.tomakehurst.wiremock.extension.ExtensionFactory;
import com.github.tomakehurst.wiremock.extension.WireMockServices;
import java.util.List;

public class JwtExtensionFactory implements ExtensionFactory {

    @Override
    public List<Extension> create(WireMockServices services) {
        final Admin admin = services.getAdmin();
        final JwtSigningKeySettings jwtSigningKeySettings = new JwtSigningKeySettings(admin);

        return List.of(
                jwtSigningKeySettings,
                new JwtHelpersExtension(jwtSigningKeySettings)
        );
    }
}
