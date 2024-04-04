package org.wiremock.extension.jwt;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.tomakehurst.wiremock.common.Json;
import java.util.List;
import java.util.Optional;

public class Rsa256JsonWebKeySet {

    private final List<Rsa256JsonWebKey> keys;

    public Rsa256JsonWebKeySet(@JsonProperty("keys") List<Rsa256JsonWebKey> keys) {
        this.keys = keys;
    }

    public List<Rsa256JsonWebKey> getKeys() {
        return keys;
    }

    public Optional<Rsa256JsonWebKey> getKey(String keyId) {
        return keys.stream()
                .filter(key -> keyId.equals(key.kid))
                .findFirst();
    }

    public static Rsa256JsonWebKeySet parse(String json) {
        return Json.read(json, Rsa256JsonWebKeySet.class);
    }
}
