/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
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
            "/fifth/sixth", 1
    );
    public static Map<String, Integer> STATUS_COUNT = Map.of(
            "active",16);

    public static int USERS_COUNT_NULL_SECURITY_QUESTION = 16;

    public static Map<String, Integer> LINKED_ACCOUNT_COUNT_PRIVILEGE = Map.of(
            "postMighty",5);


}
