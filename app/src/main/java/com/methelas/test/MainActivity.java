package com.methelas.test;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.methelas.utilities.securestore.SecureStore;
import com.methelas.utilities.securestore.exceptions.AlreadyDefinedAliasException;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        String data = "SECRET STRING";
        String alias = "test";
        int validity = 1;

        SecureStore.delete(alias);

        try {
            boolean b = SecureStore.insert(this, alias, validity, data);
            Log.e("SAVE", b + "");
        } catch (AlreadyDefinedAliasException e) {
            e.printStackTrace();
        }

        try {

            final String directory = getFilesDir().getAbsolutePath() + File.separator + alias;

            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(new File(directory)));

            byte[] buffer = new byte[1000];
            int bufferSize = 0;
            String result = "";
            while ((bufferSize = bis.read(buffer)) != -1) {
                result += new String(buffer, 0, bufferSize, "UTF-8");
            }
            bis.close();

            Log.e("EXTRACTED-CIPHERED", result + "abc");

        } catch (Exception e) {
            e.printStackTrace();
        }


        try {
            String exracteddata = SecureStore.extract(this, alias);

            Log.e("EXTRACTED", exracteddata);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
