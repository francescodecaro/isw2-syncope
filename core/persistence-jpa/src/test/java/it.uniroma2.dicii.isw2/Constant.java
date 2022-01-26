package it.uniroma2.dicii.isw2;

import java.util.HashMap;
import java.util.Map;

public class Constant {
    public static int USERS_COUNT = 16;
    public static Map<String, Integer> REALM_COUNT = Map.of(
            "/",4,
            "/even", 6,
            "/even/three", 4,
            "/even/fourth", 1,
            "/sixth", 1
    );
    public static Map<String, Integer> STATUS_COUNT = Map.of(
            "active",16);

    public static int USERS_COUNT_NULL_SECURITY_QUESTION = 16;

    public static Map<String, Integer> LINKED_ACCOUNT_COUNT_PRIVILEGE = Map.of(
            "postMighty",5);


}
