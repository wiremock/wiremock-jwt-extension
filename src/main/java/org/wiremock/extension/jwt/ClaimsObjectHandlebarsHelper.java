package org.wiremock.extension.jwt;

import java.util.HashMap;
import java.util.Map;

import com.github.jknack.handlebars.Options;
import com.github.tomakehurst.wiremock.extension.responsetemplating.helpers.HandlebarsHelper;

public class ClaimsObjectHandlebarsHelper extends HandlebarsHelper<Object> {

    @Override
    public Object apply(Object context, Options options) {
        Map<String, Object> result = new HashMap<>();
        // Process each key-value pair from the options hash
        options.hash.forEach((key, value) -> {
            // Convert each key-value pair to a nested structure if the key contains dots
            Map<String, Object> map = new HashMap<>();
            map.put(key, value);
            result.putAll(map);
        });

        return result;
    }
}
