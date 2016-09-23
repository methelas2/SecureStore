package com.methelas.utilities.securestore;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

/**
 * Created by Łukasz Nowak on 23.09.16.
 */
class Utils {

    public static KeyPair generateKeyPair(Context ctx, String alias, int validity) {

        Calendar validityStart = Calendar.getInstance();
        Calendar validityEnd = Calendar.getInstance();
        validityEnd.add(Calendar.MONTH, validity);

        try {
            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(ctx)
                    .setAlias(alias)
                    .setKeyType("RSA")
                    .setKeySize(2048)
                    .setSubject(new X500Principal("CN=" + alias))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(validityStart.getTime())
                    .setEndDate(validityEnd.getTime())
                    .build();

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            generator.initialize(spec);

            return generator.generateKeyPair();

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
