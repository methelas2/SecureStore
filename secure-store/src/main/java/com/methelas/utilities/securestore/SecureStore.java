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

import com.methelas.utilities.securestore.exceptions.AlreadyDefinedAliasException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

/**
 * Created by methelas on 23.09.16.
 */
public class SecureStore {

    // ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===

    public static boolean insert(Context ctx, String alias, int validity, String data) throws AlreadyDefinedAliasException {

        final String directory = ctx.getFilesDir().getAbsolutePath() + File.separator + alias;

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeystore");
            keyStore.load(null);

            if (keyStore.containsAlias(alias)) {
                throw new AlreadyDefinedAliasException("Alias " + alias + " is already defined!");
            }

            Utils.generateKeyPair(ctx, alias, validity);

            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
            RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

            Cipher outputCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            outputCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            CipherOutputStream cos = new CipherOutputStream(
                    new FileOutputStream(directory), outputCipher);
            cos.write(data.getBytes("UTF-8"));
            cos.close();

            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    // ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===

    public static String extract(Context ctx, String alias) {

        final String directory = ctx.getFilesDir().getAbsolutePath() + File.separator + alias;

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeystore");
            keyStore.load(null);

            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);
            PrivateKey privateKey = (PrivateKey) privateKeyEntry.getPrivateKey();

            Cipher inputCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            inputCipher.init(Cipher.DECRYPT_MODE, privateKey);

            CipherInputStream cis =
                    new CipherInputStream(new FileInputStream(directory),
                            inputCipher);

            byte[] buffer = new byte[1000];
            int bufferSize = 0;
            String result = "";
            while ((bufferSize = cis.read(buffer)) != -1) {
                result += new String(buffer, 0, bufferSize, "UTF-8");
            }
            cis.close();

            return result;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===

    public static boolean delete(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeystore");
            keyStore.load(null);

            keyStore.deleteEntry(alias);

            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    // ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===

}
