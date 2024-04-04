package org.wiremock.extension.jwt;

import com.github.tomakehurst.wiremock.extension.MappingsLoaderExtension;
import com.github.tomakehurst.wiremock.stubbing.StubMappings;

public class JwtInitialiser implements MappingsLoaderExtension {

    private final JwtSigningKeySettings jwtSigningKeySettings;
    
    private boolean initialised = false;

    public JwtInitialiser(JwtSigningKeySettings jwtSigningKeySettings) {
        this.jwtSigningKeySettings = jwtSigningKeySettings;
    }

    @Override
    public void loadMappingsInto(StubMappings stubMappings) {
        initialise();
    }

    private void initialise() {
        if (!initialised) {
            synchronized (this) {
                if (!initialised) {
                    jwtSigningKeySettings.initialise();
                    initialised = true;
                }
            }
        }
    }

    @Override
    public String getName() {
        return "jwt-initialiser";
    }
}
