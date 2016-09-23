package com.methelas.utilities.securestore;

/*
Copyright 2016 by methelas

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

import android.content.Context;
import android.security.KeyPairGeneratorSpec;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

/**
 * Created by methelas on 23.09.16.
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
