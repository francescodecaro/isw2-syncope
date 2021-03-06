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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.persistence.api.attrvalue.validation.InvalidEntityException;
import org.apache.syncope.core.persistence.api.dao.*;
import org.apache.syncope.core.persistence.api.entity.Role;
import org.apache.syncope.core.persistence.api.entity.group.Group;
import org.apache.syncope.core.persistence.api.entity.resource.ExternalResource;
import org.apache.syncope.core.persistence.api.entity.user.LinkedAccount;
import org.apache.syncope.core.persistence.api.entity.user.SecurityQuestion;
import org.apache.syncope.core.persistence.api.entity.user.UMembership;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.persistence.jpa.PersistenceTestContext;
import org.apache.syncope.core.spring.policy.AccountPolicyException;
import org.apache.syncope.core.spring.security.DelegatedAdministrationException;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.rules.SpringClassRule;
import org.springframework.test.context.junit4.rules.SpringMethodRule;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.NoResultException;

import static org.junit.Assert.*;


@RunWith(Parameterized.class)
@ContextConfiguration(classes = { PersistenceTestContext.class })
@Transactional("Master")
public class UserDAOTest {

    @ClassRule
    public static final SpringClassRule src = new SpringClassRule();

    @Rule
    public final SpringMethodRule smr = new SpringMethodRule();

    @Autowired
    private UserDAO userDAO;

    @Autowired
    private SecurityQuestionDAO securityQuestionDAO;

    @Autowired
    private ExternalResourceDAO externalResourceDAO;

    @Parameterized.Parameters
    public static Collection params() {

        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2010);
        calendar.set(Calendar.MONTH, 9);
        calendar.set(Calendar.DAY_OF_MONTH, 20);
        calendar.set(Calendar.HOUR_OF_DAY, 11);
        calendar.set(Calendar.MINUTE, 0);
        calendar.set(Calendar.SECOND, 0);
        Date lastChange = calendar.getTime();


        UserParam userRossini = new UserParam("1417acbe-cbf6-4277-9372-e75e04f97000",
               "rossini", "active", false,
                "admin", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                CipherAlgorithm.SHA1);

        UserParam userRossiniInvalidUsername = new UserParam("416300fd-8a18-4f00-8b35-159235c12f7a",
                "rossini", "active", false,
                "admin", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                CipherAlgorithm.SHA1);

        UserParam userBellini = new UserParam("c9b2dec2-00a7-4855-97c0-d854842b4b24",
                "bellini", "active", false,
                "admin", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                CipherAlgorithm.SHA1);

        UserParam userPuccini = new UserParam("823074dc-d280-436d-a7dd-07399fae48ec",
                "puccini", "active", false,
                "admin", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                CipherAlgorithm.SHA1);

        UserParam userAdmin = new UserParam("6f350d35-8230-4c8a-b724-d3c50781bfe1",
                "rossini", "active", false,
                "admin", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                CipherAlgorithm.SHA1);

        UserParam userAnonymous = new UserParam("e4ed422c-c367-41c1-8dfc-fa7136893247",
                "rossini", "active", false,
                "admin", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                CipherAlgorithm.SHA1);

        UserParam userNullUsername = new UserParam("9a5c04a0-225a-4884-8771-9161e002b431",
                null, "active", false,
                "admin", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                CipherAlgorithm.SHA1);


        Collection<RoleParam> rossiniRoles = Arrays.asList(
                new RoleParam(
                        "Other",
                        new HashSet<>(Arrays.asList("SCHEMA_READ", "GROUP_READ", "USER_REQUEST_FORM_CLAIM")),
                        Arrays.asList("722f3d84-9c2b-4525-8f6e-e4b82c55a36c"),
                        Arrays.asList("postMighty")
                )
        );

        Collection<RoleParam> userNullUsernameRoles = Arrays.asList(
                new RoleParam(
                        "Other",
                        new HashSet<>(Arrays.asList("SCHEMA_READ", "GROUP_READ", "USER_REQUEST_FORM_CLAIM")),
                        Arrays.asList("722f3d84-9c2b-4525-8f6e-e4b82c55a36c"),
                        Arrays.asList("postMighty")
                )
        );

        Collection<GroupParam> rossiniGroups = Arrays.asList(
                new GroupParam("37d15e4c-cdc1-460b-a591-8505c8133806",
                        "root", "e4c28e7a-9dbf-4ee7-9441-93812a0d4a28",
                        "admin", "admin"),
                new GroupParam("f779c0d4-633b-4be5-8f57-32eb478a3ca5", "otherchild",
                        "e4c28e7a-9dbf-4ee7-9441-93812a0d4a28", "admin", "admin")
        );

        Collection<GroupParam> userNullUsernameGroups = Arrays.asList(
                new GroupParam("37d15e4c-cdc1-460b-a591-8505c8133806",
                        "root", "e4c28e7a-9dbf-4ee7-9441-93812a0d4a28",
                        "admin", "admin")
        );


        UserParam userNullPassword = new UserParam("496ca641-2aaa-4443-870b-1eacad703ad5",
                null, "active", false,
                "admin", null,
                CipherAlgorithm.SHA1);

        UserParam nullPasswordAllowPolicyUser = new UserParam("45fa1afc-f667-4b5b-9a8d-edbd64b11f57",
                "nullPasswordAllowPolicyUser", "active", false,
                "admin", null,
                CipherAlgorithm.SHA1);

        UserParam notAllowNullPasswordPolicyUser = new UserParam("a2028c09-a748-447c-ab83-a6b2602a7943",
                "notAllowNullPasswordPolicyUser", "active", false,
                "admin", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                CipherAlgorithm.SHA1);

        UserParam notAllowNullPasswordPolicyUser2 = new UserParam("253b23b8-2d7e-401e-bce8-e31f0ff6d464",
                "notAllowNullPasswordPolicyUser2", "active", false,
                "admin", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                CipherAlgorithm.SHA1);

        UserParam notAllowNullPasswordPolicyUser3 = new UserParam("61f3189f-1a37-4a05-a41e-1d9fbb9cb4cb",
                "notAllowNullPasswordPolicyUser3", "active", false,
                "admin", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                CipherAlgorithm.SHA1);

        UserParam notAllowNullPasswordPolicyUser4 = new UserParam("5b021352-cce0-4c0c-a44d-3891b067abba",
                "notAllowNullPasswordPolicyUser4", "active", false,
                "admin", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                CipherAlgorithm.SHA1);

        UserParam realmWithNoPolicyUser = new UserParam("bd79a57d-381b-4df3-82c1-4a5105476b3e",
                "realmWithNoPolicyUser", "active", false,
                "admin", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                CipherAlgorithm.SHA1);

        Collection<String> rossiniResources = Arrays.asList("resource-testdb2", "ws-target-resource-timeout");
        Collection<String> belliniResources = Arrays.asList(
                "resource-testdb2",
                "ws-target-resource-delete",
                "ws-target-resource-2",
                "ws-target-resource-1",
                "ws-target-resource-nopropagation"
        );

        Collection<String> pucciniResources = Arrays.asList(
                "resource-testdb2"
        );

        Collection<String> userNullUsernameResources = Arrays.asList();
        Collection<String> userAnonymousResources = Arrays.asList();


        Set<String> validAuthRealmsSet = new HashSet<>();
        validAuthRealmsSet.add("c5b75db1-fce7-470f-b780-3b9934d82a9d");
        validAuthRealmsSet.add("e4c28e7a-9dbf-4ee7-9441-93812a0d4a28");
        validAuthRealmsSet.add("e4c28e7a-9dbf-4ee7-9441-93812a0d4a28@37d15e4c-cdc1-460b-a591-8505c8133806");

        Set<String> validAuthRealmsSet2 = new HashSet<>();
        validAuthRealmsSet.add("c5b75db1-fce7-470f-b780-3b9934d82a9d");
        validAuthRealmsSet.add("e4c28e7a-9dbf-4ee7-9441-93812a0d4a28");


        Collection<String> validGroupsSet = Arrays.asList(new String[]{
            "37d15e4c-cdc1-460b-a591-8505c8133806",
            "f779c0d4-633b-4be5-8f57-32eb478a3ca5"
        });


        Collection<LinkedAccountParam> rossiniLinkedAccountsParam = Arrays.asList(
                new LinkedAccountParam("connObjectKeyValue",
                userRossini.getKey(), false),
                new LinkedAccountParam("connObjectKeyValue2",
                        userRossini.getKey(), false)
        );

        Collection<LinkedAccountParam> rossiniInvalidUsernameLinkedAccountsParam = Arrays.asList(
                new LinkedAccountParam("connObjectKeyValue4",
                        userRossini.getKey(), false)
        );

        Collection<LinkedAccountParam> belliniLinkedAccountsParam = Arrays.asList(
                new LinkedAccountParam("connObjectKeyValue5",
                        userBellini.getKey(), false)
        );

        return Arrays.asList(new Object[][]{
                // username: { valid_username, empty, null }
                // minimal test suite for findKey():
                // [ "rossini", "", null ]

                // page: > 0, page <= totalPages (totalPages = totalItems / itemsPerPage = 5 / itemsPerPage)
                // itemsPerPage >= 0
                // page: { 0, page = totalPages, page = totalPages + 1}, itemsPerPage: { 0, 1 }
                // minimal test suite for findAll()
                // [ { page: 0, itemsPerPage: 0 }, { page: 2, itemsPerPage: 3 }, { page: 2, itemsPerPage: 10 } ]

                // key: { valid_key, empty, null }
                // minimal test suite for findUsername():
                // [ "1417acbe-cbf6-4277-9372-e75e04f97000", "", null ]

                // key: { valid_key, empty, null }
                // minimal test suite for findMembership():
                // [ "6d8a7dc0-d4bc-4b7e-b058-abcd3df28f28", "", null ]

                // authRealms: {valid_set, empty, null }
                // key: { valid_key, empty, null }
                // realm: { valid_key, empty, null }
                // groups: { valid_collection, empty, null }
                // minimal test suite for securityChecks():
                // [
                // { authRealms: valid_set, key: valid_key, realm: valid_key, groups: valid_collection },
                // { authRealms: empty, key: empty, realm: empty, groups: empty },
                // { authRealms: null, key: null, realm: null, groups: null },
                // ]

                // token: { valid_token, empty, null }
                // minimal test suite for findByToken():
                // [ "f21d52aa-e39e-4ec4-b3ed-21e3d3bd269a", "", null ]

                // security_key: { valid, empty, null }
                // minimal test suite for findBySecurityQuestion():
                // [ ""887028ea-66fc-41e7-b397-620d7ea6dfbb"", "", null ]
                {
                    new FindKeyParameters("rossini", "1417acbe-cbf6-4277-9372-e75e04f97000", userRossini),
                    new FindAllParameters(0, 0, 0 ),
                    new FindUsernameParameters(userRossini.getKey(), "rossini", lastChange, Pair.of(false, false), false, "Cannot invoke \"org.apache.syncope.core.persistence.api.entity.user.User.removeClearPassword()\" because \"user\" is null" ),
                    new FindMembershipParameters("6d8a7dc0-d4bc-4b7e-b058-abcd3df28f28", false, "1417acbe-cbf6-4277-9372-e75e04f97000", "f779c0d4-633b-4be5-8f57-32eb478a3ca5"),
                    new SecurityChecksParameters(validAuthRealmsSet, userRossini.getKey(), "c5b75db1-fce7-470f-b780-3b9934d82a9d", validGroupsSet, false),
                    new FindByTokenParameters("f21d52aa-e39e-4ec4-b3ed-21e3d3bd269a", userRossini, false ),
                    new FindBySecurityQuestionParameters("887028ea-66fc-41e7-b397-620d7ea6dfbb", 0 ),
                    new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups, rossiniResources),
                    new FindAllResourcesParameters(userRossini,  rossiniResources, true, DelegatedAdministrationException.class),
                    new LinkedAccountExistsParameters(userRossini.getKey(), "connObjectKeyValue", "ws-target-resource-timeout", true, rossiniLinkedAccountsParam, false)
                },
                {
                    new FindKeyParameters("", null, null ),
                    new FindAllParameters(1, 1, 1 ),
                    new FindUsernameParameters("", null, null, null, true, null),
                    new FindMembershipParameters("", true, null, null),
                    new SecurityChecksParameters(Collections.emptySet(), "", "", Collections.emptyList(), true),
                    new FindByTokenParameters("", null, true ),
                    new FindBySecurityQuestionParameters("", Constant.USERS_COUNT_NULL_SECURITY_QUESTION ),
                    new FindAllRolesAndGroupsParameters(null, Collections.emptyList(), true, Collections.emptyList(), Collections.emptyList()),
                    new FindAllResourcesParameters(null,  Collections.emptyList(), true, NullPointerException.class),
                    new LinkedAccountExistsParameters("", "", "", false, Collections.emptyList(), true)
                },
                {
                    new FindKeyParameters(null, null, userNullUsername ),
                    new FindAllParameters(2, 3, 3 ),
                    new FindUsernameParameters(null, null, null, null, true, null ),
                    new FindMembershipParameters(null, true, null, null),
                    new SecurityChecksParameters(Collections.emptySet(), "", "", Collections.emptyList(), true),
                    new FindByTokenParameters(null, null, true ),
                    new FindBySecurityQuestionParameters(null, Constant.USERS_COUNT_NULL_SECURITY_QUESTION ),
                    new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups, rossiniResources),
                    new FindAllResourcesParameters(userBellini,  belliniResources, true, DelegatedAdministrationException.class),
                    new LinkedAccountExistsParameters(null, null, null, false, Collections.emptyList(), true)
                },
                {
                    new FindKeyParameters("verd", null, null ),
                    new FindAllParameters(2, 20, 0 ),
                    new FindUsernameParameters(userRossiniInvalidUsername.getKey(), "!rossini", lastChange, null, true, "User [InvalidUsername]" ),
                    new FindMembershipParameters("40e409a4-d870-4792-b820-30668f1269b9", false, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "bf825fe1-7320-4a54-bd64-143b5c18ab97"),
                    new SecurityChecksParameters(validAuthRealmsSet2, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "c5b75db1-fce7-470f-b780-3b9934d82a9d", validGroupsSet, true),
                    new FindByTokenParameters("1417acbe-cbf6-4277-9372-e75e04f9700", null, true ),
                    new FindBySecurityQuestionParameters("1417acbe-cbf6-4277-9372-e75e04f9700", Constant.USERS_COUNT_NULL_SECURITY_QUESTION ),
                    new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups, rossiniResources),
                    new FindAllResourcesParameters(userPuccini,  pucciniResources, true, DelegatedAdministrationException.class),
                    new LinkedAccountExistsParameters(userRossiniInvalidUsername.getKey(), "connObjectKeyValue3", "ws-target-resource-timeout", false, rossiniInvalidUsernameLinkedAccountsParam, true)
                },
                {
                    // Not Used
                    new FindKeyParameters("verd", null, null ),
                    // Not Used
                    new FindAllParameters(2, 20, 0 ),
                    new FindUsernameParameters(userBellini.getKey(), "bellini", lastChange, null, true, "User [InvalidUsername]" ),
                    // Not Used
                    new FindMembershipParameters("40e409a4-d870-4792-b820-30668f1269b9", false, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "bf825fe1-7320-4a54-bd64-143b5c18ab97"),
                    new SecurityChecksParameters(validAuthRealmsSet, userRossini.getKey(), "", validGroupsSet, false),
                    // Not Used
                    new FindByTokenParameters("1417acbe-cbf6-4277-9372-e75e04f9700", null, true ),
                    // Not Used
                    new FindBySecurityQuestionParameters("1417acbe-cbf6-4277-9372-e75e04f9700", Constant.USERS_COUNT_NULL_SECURITY_QUESTION ),
                    // Not Used
                    new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups, rossiniResources),
                    // Not Used
                    new FindAllResourcesParameters(userAnonymous,  userAnonymousResources, true, DelegatedAdministrationException.class),
                    // Not Used
                    new LinkedAccountExistsParameters(userRossiniInvalidUsername.getKey(), "connObjectKeyValue3", "ws-target-resource-timeout", false, rossiniInvalidUsernameLinkedAccountsParam, true)
                },
                {
                        // Not Used
                        new FindKeyParameters("verd", null, null ),
                        // Not Used
                        new FindAllParameters(2, 20, 0 ),
                        new FindUsernameParameters(userAdmin.getKey(), "admin", lastChange, null, true, "User [InvalidUsername]" ),
                        // Not Used
                        new FindMembershipParameters("40e409a4-d870-4792-b820-30668f1269b9", false, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "bf825fe1-7320-4a54-bd64-143b5c18ab97"),
                        new SecurityChecksParameters(validAuthRealmsSet, userRossini.getKey(), "", Collections.emptySet(), true),
                        // Not Used
                        new FindByTokenParameters("1417acbe-cbf6-4277-9372-e75e04f9700", null, true ),
                        // Not Used
                        new FindBySecurityQuestionParameters("1417acbe-cbf6-4277-9372-e75e04f9700", Constant.USERS_COUNT_NULL_SECURITY_QUESTION ),
                        new FindAllRolesAndGroupsParameters(userNullUsername, userNullUsernameRoles, false, userNullUsernameGroups, userNullUsernameResources),
                        // Not Used
                        new FindAllResourcesParameters(userPuccini,  pucciniResources, true, DelegatedAdministrationException.class),
                        // Not Used
                        new LinkedAccountExistsParameters(userRossiniInvalidUsername.getKey(), "connObjectKeyValue3", "ws-target-resource-timeout", false, rossiniInvalidUsernameLinkedAccountsParam, true)
                },
                {
                        // Not Used
                        new FindKeyParameters("verd", null, null ),
                        // Not Used
                        new FindAllParameters(2, 20, 0 ),
                        new FindUsernameParameters(userAnonymous.getKey(), "anonymous", lastChange, null, true, "User [InvalidUsername]" ),
                        // Not Used
                        new FindMembershipParameters("40e409a4-d870-4792-b820-30668f1269b9", false, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "bf825fe1-7320-4a54-bd64-143b5c18ab97"),
                        // Not Used
                        new SecurityChecksParameters(validAuthRealmsSet, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "c5b75db1-fce7-470f-b780-3b9934d82a9d", validGroupsSet, false),
                        // Not Used
                        new FindByTokenParameters("1417acbe-cbf6-4277-9372-e75e04f9700", null, true ),
                        // Not Used
                        new FindBySecurityQuestionParameters("1417acbe-cbf6-4277-9372-e75e04f9700", Constant.USERS_COUNT_NULL_SECURITY_QUESTION ),
                        // Not Used
                        new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups, rossiniResources),
                        // Not Used
                        new FindAllResourcesParameters(realmWithNoPolicyUser,  Collections.emptyList(), true, DelegatedAdministrationException.class),
                        // Not Used
                        new LinkedAccountExistsParameters(userRossiniInvalidUsername.getKey(), "connObjectKeyValue3", "ws-target-resource-timeout", false, rossiniInvalidUsernameLinkedAccountsParam, true)
                },
                {
                        // Not Used
                        new FindKeyParameters("verd", null, null ),
                        // Not Used
                        new FindAllParameters(2, 20, 0 ),
                        new FindUsernameParameters(userNullUsername.getKey(), null, lastChange, null, true, "User [InvalidUsername]" ),
                        // Not Used
                        new FindMembershipParameters("40e409a4-d870-4792-b820-30668f1269b9", false, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "bf825fe1-7320-4a54-bd64-143b5c18ab97"),
                        // Not Used
                        new SecurityChecksParameters(validAuthRealmsSet2, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "c5b75db1-fce7-470f-b780-3b9934d82a9d", validGroupsSet, true),
                        // Not Used
                        new FindByTokenParameters("1417acbe-cbf6-4277-9372-e75e04f9700", null, true ),
                        // Not Used
                        new FindBySecurityQuestionParameters("1417acbe-cbf6-4277-9372-e75e04f9700", Constant.USERS_COUNT_NULL_SECURITY_QUESTION ),
                        // Not Used
                        new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups, rossiniResources),
                        // Not Used
                        new FindAllResourcesParameters(userPuccini,  pucciniResources, true, DelegatedAdministrationException.class),
                        // Not Used
                        new LinkedAccountExistsParameters(userRossiniInvalidUsername.getKey(), "connObjectKeyValue3", "ws-target-resource-timeout", false, rossiniInvalidUsernameLinkedAccountsParam, true)
                },
                {
                        // Not Used
                        new FindKeyParameters("verd", null, null ),
                        // Not Used
                        new FindAllParameters(2, 20, 0 ),
                        new FindUsernameParameters(userNullPassword.getKey(), "nullPassword", lastChange, null, true, "User [InvalidPassword]" ),
                        // Not Used
                        new FindMembershipParameters("40e409a4-d870-4792-b820-30668f1269b9", false, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "bf825fe1-7320-4a54-bd64-143b5c18ab97"),
                        // Not Used
                        new SecurityChecksParameters(validAuthRealmsSet2, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "c5b75db1-fce7-470f-b780-3b9934d82a9d", validGroupsSet, true),
                        // Not Used
                        new FindByTokenParameters("1417acbe-cbf6-4277-9372-e75e04f9700", null, true ),
                        // Not Used
                        new FindBySecurityQuestionParameters("1417acbe-cbf6-4277-9372-e75e04f9700", Constant.USERS_COUNT_NULL_SECURITY_QUESTION ),
                        // Not Used
                        new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups, rossiniResources),
                        // Not Used
                        new FindAllResourcesParameters(userPuccini,  pucciniResources, true, DelegatedAdministrationException.class),
                        // Not Used
                        new LinkedAccountExistsParameters(userRossiniInvalidUsername.getKey(), "connObjectKeyValue3", "ws-target-resource-timeout", false, rossiniInvalidUsernameLinkedAccountsParam, true)
                },
                {
                        // Not Used
                        new FindKeyParameters("verd", null, null ),
                        // Not Used
                        new FindAllParameters(2, 20, 0 ),
                        new FindUsernameParameters(nullPasswordAllowPolicyUser.getKey(), "nullPasswordAllowPolicyUser", lastChange, Pair.of(false, false), false, "" ),
                        // Not Used
                        new FindMembershipParameters("40e409a4-d870-4792-b820-30668f1269b9", false, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "bf825fe1-7320-4a54-bd64-143b5c18ab97"),
                        // Not Used
                        new SecurityChecksParameters(validAuthRealmsSet2, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "c5b75db1-fce7-470f-b780-3b9934d82a9d", validGroupsSet, true),
                        // Not Used
                        new FindByTokenParameters("1417acbe-cbf6-4277-9372-e75e04f9700", null, true ),
                        // Not Used
                        new FindBySecurityQuestionParameters("1417acbe-cbf6-4277-9372-e75e04f9700", Constant.USERS_COUNT_NULL_SECURITY_QUESTION ),
                        // Not Used
                        new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups, rossiniResources),
                        // Not Used
                        new FindAllResourcesParameters(userPuccini,  pucciniResources, true, DelegatedAdministrationException.class),
                        // Not Used
                        new LinkedAccountExistsParameters(userRossiniInvalidUsername.getKey(), "connObjectKeyValue3", "ws-target-resource-timeout", false, rossiniInvalidUsernameLinkedAccountsParam, true)
                },
                {
                        // Not Used
                        new FindKeyParameters("verd", null, null ),
                        // Not Used
                        new FindAllParameters(2, 20, 0 ),
                        new FindUsernameParameters(notAllowNullPasswordPolicyUser.getKey(), "notAllowNullPasswordPolicyUser", lastChange, Pair.of(false, false), false, "" ),
                        // Not Used
                        new FindMembershipParameters("40e409a4-d870-4792-b820-30668f1269b9", false, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "bf825fe1-7320-4a54-bd64-143b5c18ab97"),
                        // Not Used
                        new SecurityChecksParameters(validAuthRealmsSet2, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "c5b75db1-fce7-470f-b780-3b9934d82a9d", validGroupsSet, true),
                        // Not Used
                        new FindByTokenParameters("1417acbe-cbf6-4277-9372-e75e04f9700", null, true ),
                        // Not Used
                        new FindBySecurityQuestionParameters("1417acbe-cbf6-4277-9372-e75e04f9700", Constant.USERS_COUNT_NULL_SECURITY_QUESTION ),
                        // Not Used
                        new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups, rossiniResources),
                        // Not Used
                        new FindAllResourcesParameters(userPuccini,  pucciniResources, true, DelegatedAdministrationException.class),
                        // Not Used
                        new LinkedAccountExistsParameters(userRossiniInvalidUsername.getKey(), "connObjectKeyValue3", "ws-target-resource-timeout", false, rossiniInvalidUsernameLinkedAccountsParam, true)
                },
                {
                        // Not Used
                        new FindKeyParameters("verd", null, null ),
                        // Not Used
                        new FindAllParameters(2, 20, 0 ),
                        new FindUsernameParameters(notAllowNullPasswordPolicyUser2.getKey(), "notAllowNullPasswordPolicyUser2", lastChange, Pair.of(false, false), false, ""  ),
                        // Not Used
                        new FindMembershipParameters("40e409a4-d870-4792-b820-30668f1269b9", false, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "bf825fe1-7320-4a54-bd64-143b5c18ab97"),
                        // Not Used
                        new SecurityChecksParameters(validAuthRealmsSet2, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "c5b75db1-fce7-470f-b780-3b9934d82a9d", validGroupsSet, true),
                        // Not Used
                        new FindByTokenParameters("1417acbe-cbf6-4277-9372-e75e04f9700", null, true ),
                        // Not Used
                        new FindBySecurityQuestionParameters("1417acbe-cbf6-4277-9372-e75e04f9700", Constant.USERS_COUNT_NULL_SECURITY_QUESTION ),
                        // Not Used
                        new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups, rossiniResources),
                        // Not Used
                        new FindAllResourcesParameters(userPuccini,  pucciniResources, true, DelegatedAdministrationException.class),
                        // Not Used
                        new LinkedAccountExistsParameters(userRossiniInvalidUsername.getKey(), "connObjectKeyValue3", "ws-target-resource-timeout", false, rossiniInvalidUsernameLinkedAccountsParam, true)
                },
                {
                        // Not Used
                        new FindKeyParameters("verd", null, null ),
                        // Not Used
                        new FindAllParameters(2, 20, 0 ),
                        new FindUsernameParameters(notAllowNullPasswordPolicyUser3.getKey(), "notAllowNullPasswordPolicyUser3", lastChange, Pair.of(false, false), false , "" ),
                        // Not Used
                        new FindMembershipParameters("40e409a4-d870-4792-b820-30668f1269b9", false, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "bf825fe1-7320-4a54-bd64-143b5c18ab97"),
                        // Not Used
                        new SecurityChecksParameters(validAuthRealmsSet2, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "c5b75db1-fce7-470f-b780-3b9934d82a9d", validGroupsSet, true),
                        // Not Used
                        new FindByTokenParameters("1417acbe-cbf6-4277-9372-e75e04f9700", null, true ),
                        // Not Used
                        new FindBySecurityQuestionParameters("1417acbe-cbf6-4277-9372-e75e04f9700", Constant.USERS_COUNT_NULL_SECURITY_QUESTION ),
                        // Not Used
                        new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups, rossiniResources),
                        // Not Used
                        new FindAllResourcesParameters(userPuccini,  pucciniResources, true, DelegatedAdministrationException.class),
                        // Not Used
                        new LinkedAccountExistsParameters(userRossiniInvalidUsername.getKey(), "connObjectKeyValue3", "ws-target-resource-timeout", false, rossiniInvalidUsernameLinkedAccountsParam, true)
                },
                {
                        // Not Used
                        new FindKeyParameters("verd", null, null ),
                        // Not Used
                        new FindAllParameters(2, 20, 0 ),
                        new FindUsernameParameters(notAllowNullPasswordPolicyUser4.getKey(), "notAllowNullPasswordPolicyUser4", lastChange, Pair.of(false, true), false , "" ),
                        // Not Used
                        new FindMembershipParameters("40e409a4-d870-4792-b820-30668f1269b9", false, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "bf825fe1-7320-4a54-bd64-143b5c18ab97"),
                        // Not Used
                        new SecurityChecksParameters(validAuthRealmsSet2, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "c5b75db1-fce7-470f-b780-3b9934d82a9d", validGroupsSet, true),
                        // Not Used
                        new FindByTokenParameters("1417acbe-cbf6-4277-9372-e75e04f9700", null, true ),
                        // Not Used
                        new FindBySecurityQuestionParameters("1417acbe-cbf6-4277-9372-e75e04f9700", Constant.USERS_COUNT_NULL_SECURITY_QUESTION ),
                        // Not Used
                        new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups, rossiniResources),
                        // Not Used
                        new FindAllResourcesParameters(userPuccini,  pucciniResources, true, DelegatedAdministrationException.class),
                        // Not Used
                        new LinkedAccountExistsParameters(userRossiniInvalidUsername.getKey(), "connObjectKeyValue3", "ws-target-resource-timeout", false, rossiniInvalidUsernameLinkedAccountsParam, true)
                },
                {
                        // Not Used
                        new FindKeyParameters("verd", null, null ),
                        // Not Used
                        new FindAllParameters(2, 20, 0 ),
                        new FindUsernameParameters(realmWithNoPolicyUser.getKey(), "realmWithNoPolicyUser", lastChange, Pair.of(false, false), false , "" ),
                        // Not Used
                        new FindMembershipParameters("40e409a4-d870-4792-b820-30668f1269b9", false, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "bf825fe1-7320-4a54-bd64-143b5c18ab97"),
                        // Not Used
                        new SecurityChecksParameters(validAuthRealmsSet2, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "c5b75db1-fce7-470f-b780-3b9934d82a9d", validGroupsSet, true),
                        // Not Used
                        new FindByTokenParameters("1417acbe-cbf6-4277-9372-e75e04f9700", null, true ),
                        // Not Used
                        new FindBySecurityQuestionParameters("1417acbe-cbf6-4277-9372-e75e04f9700", Constant.USERS_COUNT_NULL_SECURITY_QUESTION ),
                        // Not Used
                        new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups, rossiniResources),
                        // Not Used
                        new FindAllResourcesParameters(userPuccini,  pucciniResources, true, DelegatedAdministrationException.class),
                        // Not Used
                        new LinkedAccountExistsParameters(userRossiniInvalidUsername.getKey(), "connObjectKeyValue3", "ws-target-resource-timeout", false, rossiniInvalidUsernameLinkedAccountsParam, true)
                },
        });
    }

    @Parameterized.Parameter(value = 0)
    public FindKeyParameters findKeyParameters;

    @Parameterized.Parameter(value = 1)
    public FindAllParameters findAllParameters;

    @Parameterized.Parameter(value = 2)
    public FindUsernameParameters findUsernameParameters;

    @Parameterized.Parameter(value = 3)
    public FindMembershipParameters findMembershipParameters;

    @Parameterized.Parameter(value = 4)
    public SecurityChecksParameters securityChecksParameters;

    @Parameterized.Parameter(value = 5)
    public FindByTokenParameters findByTokenParameters;

    @Parameterized.Parameter(value = 6)
    public FindBySecurityQuestionParameters findBySecurityQuestion;

    @Parameterized.Parameter(value = 7)
    public FindAllRolesAndGroupsParameters findAllRolesAndGroupsParameters;

    @Parameterized.Parameter(value = 8)
    public FindAllResourcesParameters findAllResourcesParameters;

    @Parameterized.Parameter(value = 9)
    public LinkedAccountExistsParameters linkedAccountExistsParameters;



    @Test
    public void findKeyAndByUsername() {
        String key = userDAO.findKey(findKeyParameters.getUsername());
        assertEquals(findKeyParameters.getExpectedKey(), key);

        User user = userDAO.findByUsername(findKeyParameters.getUsername());
        assertUserEquals(findKeyParameters.getExpectedUser(), user);
    }

    @Test
    public void findAll() {
        List<User> users = userDAO.findAll(findAllParameters.getPage(), findAllParameters.getItemsPerPage());
        assertEquals(findAllParameters.getExpectedCount(), users.size());

        List<String> keys = userDAO.findAllKeys(findAllParameters.getPage(), findAllParameters.getItemsPerPage());
        assertEquals(findAllParameters.getExpectedCount(), keys.size());

        assertEquals(keys, users.stream().map(u -> u.getKey()).collect(Collectors.toList()));
    }

    @Test
    public void findUsernameAndLastChangeAndMembershipAndEnforcePolicies() {
        Optional<String> username = userDAO.findUsername(findUsernameParameters.getKey());
        assertEquals(findUsernameParameters.expectedUsername, !username.isPresent() ? null : username.get());

        Date lastChange = userDAO.findLastChange(findUsernameParameters.getKey());

        if (findUsernameParameters.getExpectedLastChange() != null && lastChange != null) {
            DateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            assertEquals(formatter.format(findUsernameParameters.getExpectedLastChange()), formatter.format(lastChange));
        } else if (findUsernameParameters.getExpectedLastChange() == null && lastChange == null) {
            assertTrue(true);
        } else {
            fail();
        }

        User user = userDAO.find(findUsernameParameters.getKey());
        try {
            Pair<Boolean, Boolean> policies = userDAO.enforcePolicies(user);
            assertNotNull(policies);
            assertEquals(findUsernameParameters.getExpectedPolicies().getLeft(), policies.getLeft());
            assertEquals(findUsernameParameters.getExpectedPolicies().getRight(), policies.getRight());

        } catch (NullPointerException | AccountPolicyException | InvalidEntityException e) {
            if (findUsernameParameters.isExpectToThrowException()) {
                assertEquals(findUsernameParameters.getExpectedExceptionMessage(), e.getMessage());
                assertTrue(true);
            } else {
                fail();
            }
        }

    }

    @Test
    public void findMembership() {
        UMembership membership = userDAO.findMembership(findMembershipParameters.getKey());
        if (findMembershipParameters.isExpectMembershipToBeNull()) {
            assertNull(membership);
        } else {
            assertEquals(findMembershipParameters.getExpectedUserKey(), membership.getLeftEnd().getKey());
            assertEquals(findMembershipParameters.getExpectedGroupKey(), membership.getRightEnd().getKey());
        }
    }

    @Test
    public void testSecurityChecks() {
        try {
            userDAO.securityChecks(securityChecksParameters.getAuthRealms(), securityChecksParameters.getKey(), securityChecksParameters.getRealm(), securityChecksParameters.getGroups());
            if (securityChecksParameters.isExpectToThrowException()) {
                fail();
            }
        } catch (DelegatedAdministrationException e) {
            if (securityChecksParameters.isExpectToThrowException()) {
                assertTrue(true);
            } else {
                fail();
            }
        }
    }

    @Test
    public void testFindByToken() {
        try {
            User user = userDAO.findByToken(findByTokenParameters.getToken());
            assertUserEquals(findByTokenParameters.getExpectedUser(), user);
        } catch (NoResultException e) {
            if (findByTokenParameters.isExpectToThrowException()) {
                assertTrue(true);
            } else {
                fail();
            }
        }
    }

    @Test
    public void testFindBySecurityQuestion() {
        SecurityQuestion securityQuestion = securityQuestionDAO.find(findBySecurityQuestion.getSecurityQuestionKey());
        List<User> users = userDAO.findBySecurityQuestion(securityQuestion);
        assertEquals(findBySecurityQuestion.getExpectedUsersCount(), users.size());
    }


    @Test
    public void testFindAllRolesAndGroups() {
        try {
            if (findAllRolesAndGroupsParameters.getUser() != null) {
                User user = userDAO.find(findAllRolesAndGroupsParameters.getUser().getKey());

                Collection<Role> roles = userDAO.findAllRoles(user);
                assertEquals(findAllRolesAndGroupsParameters.getExpectedRoles().size(), roles.size());
                roles.forEach(role -> {
                    RoleParam expectedRole = findAllRolesAndGroupsParameters.getExpectedRoles()
                            .stream().filter(r -> r.getKey().equals(role.getKey())).findFirst().get();
                    assertNotNull(expectedRole);
                    assertEquals(expectedRole.getEntitlements(), role.getEntitlements());
                    List<String> realms = role.getRealms().stream().map(r -> r.getKey()).collect(Collectors.toList());
                    assertEquals(expectedRole.getRealmsKeys(), realms);

                    List<String> privileges = role.getPrivileges().stream().map(p -> p.getKey()).collect(Collectors.toList());
                    assertEquals(expectedRole.getPrivilegesKeys(), privileges);
                });

                Collection<Group> groups = userDAO.findAllGroups(user);

                assertEquals(findAllRolesAndGroupsParameters.getExpectedGroups().size(), groups.size());
                groups.forEach(group -> {
                    GroupParam expectedGroup = findAllRolesAndGroupsParameters.getExpectedGroups().stream()
                            .filter(g -> g.getKey().equals(group.getKey())).findFirst().get();
                    assertNotNull(expectedGroup);
                    assertEquals(expectedGroup.getName(), group.getName());
                    assertEquals(expectedGroup.getRealm(), group.getRealm().getKey());
                    assertEquals(expectedGroup.getCreator(), group.getCreator());
                    assertEquals(expectedGroup.getLastModifier(), group.getLastModifier());
                });

                Collection<String> groupsKeys = userDAO.findAllGroupKeys(user);
                Collection<String> groupsNames = userDAO.findAllGroupNames(user);

                assertEquals(findAllRolesAndGroupsParameters.getExpectedGroups().size(), groupsKeys.size());
                assertEquals(
                        findAllRolesAndGroupsParameters.getExpectedGroups().stream().map(g -> g.getKey()).collect(Collectors.toList()),
                        groupsKeys);

                assertEquals(findAllRolesAndGroupsParameters.getExpectedGroups().size(), groupsNames.size());
                assertEquals(
                        findAllRolesAndGroupsParameters.getExpectedGroups().stream().map(g -> g.getName()).collect(Collectors.toList()),
                        groupsNames);


            } else {
                Collection<Role> roles = userDAO.findAllRoles(null);
                assertNull(roles);
            }
        } catch (NullPointerException e) {
            if (findAllRolesAndGroupsParameters.isExpectToThrowException()) {
                assertTrue(true);
            } else {
                fail();
            }
        }
    }

    @Test
    public void testFindAllResources() {
        try {
            User user = userDAO.find(findAllResourcesParameters.getUser() != null ? findAllResourcesParameters.getUser().getKey() : null);

            Collection<ExternalResource> resources = userDAO.findAllResources(user);
            assertEquals(findAllResourcesParameters.getExpectedResources().size(), resources.size());


            Collection<String> resourcesKeys = userDAO.findAllResourceKeys(user.getKey());
            assertEquals(findAllResourcesParameters.getExpectedResources().size(), resourcesKeys.size());
            assertEquals(findAllResourcesParameters.getExpectedResources(), resourcesKeys);
        } catch (DelegatedAdministrationException e) {
            if (findAllResourcesParameters.isExpectToThrowException() && findAllResourcesParameters.getExpectedException().equals(DelegatedAdministrationException.class)) {
                assertTrue(true);
            } else {
                fail();
            }
        } catch (NullPointerException e) {
            if (findAllResourcesParameters.isExpectToThrowException() && findAllResourcesParameters.getExpectedException().equals(NullPointerException.class)) {
                assertTrue(true);
            } else {
                fail();
            }
        }
    }

    @Test
    public void testLinkedAccountExists() {

        boolean result = userDAO.linkedAccountExists(linkedAccountExistsParameters.getUserKey(), linkedAccountExistsParameters.getConnObjectKeyValue());
        assertEquals(linkedAccountExistsParameters.isExpected(), result);
        List<LinkedAccount> linkedAccounts = userDAO.findLinkedAccounts(linkedAccountExistsParameters.getUserKey());
        assertEquals(linkedAccountExistsParameters.getLinkedAccounts().size(), linkedAccounts.size());

        ExternalResource externalResource = externalResourceDAO.find(linkedAccountExistsParameters.getResourceKey());
        assertEquals(linkedAccountExistsParameters.isExpectedEmpty(),
        userDAO.findLinkedAccount(externalResource, linkedAccountExistsParameters.getConnObjectKeyValue()).isEmpty());
    }


    private void assertUserEquals(UserParam expectedUser, User user) {
        if (user == null && expectedUser == null) {
            assertTrue(true);
        } else if (user != null && expectedUser != null) {
            assertEquals(expectedUser.getKey(), user.getKey());
            assertEquals(expectedUser.getStatus(), user.getStatus());
            assertEquals(expectedUser.isMustChangePassword(), user.isMustChangePassword());
            assertEquals(expectedUser.getCreator(), user.getCreator());
            assertEquals(expectedUser.getPassword(), user.getPassword());
            assertEquals(expectedUser.getCipherAlgorithm(), user.getCipherAlgorithm());
        } else {
            fail();
        }
    }


    @AllArgsConstructor
    static class FindKeyParameters {
        @Getter private String username;
        @Getter private String expectedKey;
        @Getter private UserParam expectedUser;
    }

    @AllArgsConstructor
    static class FindAllParameters {
        @Getter private int page;
        @Getter private int itemsPerPage;
        @Getter private int expectedCount;
    }

    @AllArgsConstructor
    static class FindUsernameParameters {
        @Getter private String key;
        @Getter private String expectedUsername;
        @Getter private Date expectedLastChange;
        @Getter private Pair<Boolean, Boolean> expectedPolicies;
        @Getter private boolean expectToThrowException;
        @Getter private String expectedExceptionMessage;
    }

    @AllArgsConstructor
    static class FindMembershipParameters {
        @Getter private String key;
        @Getter private boolean expectMembershipToBeNull;
        @Getter private String expectedUserKey;
        @Getter private String expectedGroupKey;
    }

    @AllArgsConstructor
    static class SecurityChecksParameters {
        @Getter private Set<String> authRealms;
        @Getter private String key;
        @Getter private String realm;
        @Getter private Collection<String> groups;
        @Getter private boolean expectToThrowException;
    }


    @AllArgsConstructor
    static class FindByTokenParameters {
        @Getter private String token;
        @Getter private UserParam expectedUser;
        @Getter private boolean expectToThrowException;
    }

    @AllArgsConstructor
    static class FindBySecurityQuestionParameters {
        @Getter private String securityQuestionKey;
        @Getter private int expectedUsersCount;
    }

    @AllArgsConstructor
    static class FindAllRolesAndGroupsParameters {
        @Getter private UserParam user;
        @Getter private Collection<RoleParam> expectedRoles;
        @Getter private boolean expectToThrowException;
        @Getter private Collection<GroupParam> expectedGroups;
        @Getter private Collection<String> expectedResources;
    }

    @AllArgsConstructor
    static class FindAllResourcesParameters {
        @Getter private UserParam user;
        @Getter private Collection<String> expectedResources;
        @Getter private boolean expectToThrowException;
        @Getter private Class<? extends Exception> expectedException;
    }


    @AllArgsConstructor
    static class LinkedAccountExistsParameters {
        @Getter private String userKey;
        @Getter private String connObjectKeyValue;
        @Getter private String resourceKey;
        @Getter private boolean expected;
        @Getter private Collection<LinkedAccountParam> linkedAccounts;
        @Getter private boolean expectedEmpty;
    }


    @AllArgsConstructor
    @Data
    static class UserParam {
        private String key;
        private String username;
        private String status;
        private boolean mustChangePassword;
        private String creator;
        private String password;
        private CipherAlgorithm cipherAlgorithm;
    }

    @AllArgsConstructor
    @Data
    static class RoleParam {
        private String key;
        private Set<String> entitlements;
        private List<String> realmsKeys;
        private List<String> privilegesKeys;
    }

    @AllArgsConstructor
    @Data
    static class GroupParam {
        private String key;
        private String name;
        private String realm;
        private String creator;
        private String lastModifier;
    }

    @AllArgsConstructor
    @Data
    static class LinkedAccountParam {
        private String connObjectKeyValue;
        private String owner;
        private boolean suspended;
    }


}
