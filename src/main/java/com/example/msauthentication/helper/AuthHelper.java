package com.example.msauthentication.helper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AuthHelper {

    public static boolean validEmail(String email) {
        return email != null && email.contains("@");
    }

    public static boolean validPassword(String password) {
        return password != null && password.length() >= 3;
    }

    public static boolean validDocument(String doc) {
        return doc != null && doc.length() >= 5;
    }

    public static String makeToken(String email, String doc) {
        String raw = email + ":" + doc + ":" + System.nanoTime();
        return Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }
}
