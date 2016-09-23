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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

/**
 * Created by methelas on 23.09.16.
 */
public class SecureStore {

    private static int BLOCK_SIZE_ENCRYPT = 100;
    private static int BLOCK_SIZE_DECRYPT = 256;

    // ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===

    /**
     * Allows to store data in applications files directory, ciphered using key stored in
     * AndroidKeyStore
     *
     * @param ctx      activity context
     * @param alias    name for stored data
     * @param validity counted in MONTHS,
     *                 eq. validity == 5 means the record will be accessible for 5 months
     * @param data     to be secured in a form of @see {@link String}
     * @return true if inserted correctly, false otherwise
     * @throws AlreadyDefinedAliasException when data under given alias already exists in this application
     */
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

            Cipher outputCipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
            outputCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] dataAsBytes = data.getBytes("UTF-8");
            int fullBlocks = dataAsBytes.length / BLOCK_SIZE_ENCRYPT;
            byte[] dataEncrypted = new byte[0];

            for (int i = 0; i < fullBlocks; i++) {

                byte[] encryptedPart =
                        outputCipher.doFinal(dataAsBytes, i * BLOCK_SIZE_ENCRYPT, BLOCK_SIZE_ENCRYPT);

                dataEncrypted = Utils.appendByteArrays(dataEncrypted, encryptedPart);
            }

            byte[] encryptedPart =
                    outputCipher.doFinal(dataAsBytes, fullBlocks * BLOCK_SIZE_ENCRYPT, dataAsBytes.length - fullBlocks * BLOCK_SIZE_ENCRYPT);

            dataEncrypted = Utils.appendByteArrays(dataEncrypted, encryptedPart);

            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(new File(directory)));
            bos.write(dataEncrypted);
            bos.flush();
            bos.close();

            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    // ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===

    /**
     * Allows to extract data stored under given alias
     *
     * @param ctx   activity context
     * @param alias of the stored data
     * @return stored data or null if data does not exist or is corrupted
     */
    public static String extract(Context ctx, String alias) {

        final String directory = ctx.getFilesDir().getAbsolutePath() + File.separator + alias;

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeystore");
            keyStore.load(null);

            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
            PrivateKey privateKey = (PrivateKey) privateKeyEntry.getPrivateKey();

            Cipher inputCipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
            inputCipher.init(Cipher.DECRYPT_MODE, privateKey);

            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(new File(directory)));

            byte[] buffer = new byte[BLOCK_SIZE_DECRYPT];
            String result = "";
            while (bis.read(buffer) != -1) {
                result += new String(inputCipher.doFinal(buffer), "UTF-8");
            }
            bis.close();

            return result;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===

    /**
     * Deletes data stored under given alias
     *
     * @param ctx   activity context
     * @param alias of the stored data
     * @return true if data was deleted completely, false otherwise
     */
    public static boolean delete(Context ctx, String alias) {

        final String directory = ctx.getFilesDir().getAbsolutePath() + File.separator + alias;

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeystore");
            keyStore.load(null);

            keyStore.deleteEntry(alias);

            File f = new File(directory);
            f.delete();

            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    // ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===== ===

}
