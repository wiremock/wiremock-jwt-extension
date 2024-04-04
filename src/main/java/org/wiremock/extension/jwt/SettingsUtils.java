package org.wiremock.extension.jwt;

import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.global.GlobalSettings;
import com.google.common.collect.ImmutableMap;
import java.util.LinkedHashMap;

public class SettingsUtils {

    public static Parameters merge(Parameters... allParameters) {
        LinkedHashMap<String, Object> builder = new LinkedHashMap<>();

        for (Parameters params: allParameters) {
            if (params != null) {
                builder.putAll(params);
            }
        }

        return Parameters.from(ImmutableMap.copyOf(builder));
    }

    public static GlobalSettings merge(GlobalSettings one, GlobalSettings two) {
        return new GlobalSettings(
                lastOrNull(one.getFixedDelay(), two.getFixedDelay()),
                lastOrNull(one.getDelayDistribution(), two.getDelayDistribution()),
                merge(one.getExtended(), two.getExtended()),
                two.getProxyPassThrough()
        );
    }

    private static <T> T lastOrNull(T... values) {
        for (int i = values.length - 1; i >= 0; i--) {
            if (values[i] != null) {
                return values[i];
            }
        }

        return null;
    }
}
