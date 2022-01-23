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
import org.apache.syncope.core.persistence.api.dao.*;
import org.apache.syncope.core.persistence.api.entity.Realm;
import org.apache.syncope.core.persistence.api.entity.Role;
import org.apache.syncope.core.persistence.api.entity.group.Group;
import org.apache.syncope.core.persistence.api.entity.resource.ExternalResource;
import org.apache.syncope.core.persistence.api.entity.user.LinkedAccount;
import org.apache.syncope.core.persistence.api.entity.user.SecurityQuestion;
import org.apache.syncope.core.persistence.api.entity.user.UMembership;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.persistence.jpa.PersistenceTestContext;
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

        Collection<RoleParam> rossiniRoles = Arrays.asList(
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


        Set<String> validAuthRealmsSet = new HashSet<>();
        validAuthRealmsSet.add("c5b75db1-fce7-470f-b780-3b9934d82a9d");
        validAuthRealmsSet.add("e4c28e7a-9dbf-4ee7-9441-93812a0d4a28");

        Collection<String> validGroupsSet = Arrays.asList(new String[]{
            "37d15e4c-cdc1-460b-a591-8505c8133806",
            "f779c0d4-633b-4be5-8f57-32eb478a3ca5"
        });


        Collection<LinkedAccountParam> linkedAccountsParam = Arrays.asList(
                new LinkedAccountParam("connObjectKeyValue",
                userRossini.getKey(), false)
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
                    new FindUsernameParameters("1417acbe-cbf6-4277-9372-e75e04f97000", "rossini", lastChange, Pair.of(false, false), false ),
                    new FindMembershipParameters("6d8a7dc0-d4bc-4b7e-b058-abcd3df28f28", false, "1417acbe-cbf6-4277-9372-e75e04f97000", "f779c0d4-633b-4be5-8f57-32eb478a3ca5"),
                    new SecurityChecksParameters(validAuthRealmsSet, "1417acbe-cbf6-4277-9372-e75e04f97000", "c5b75db1-fce7-470f-b780-3b9934d82a9d", validGroupsSet, false),
                    new FindByTokenParameters("f21d52aa-e39e-4ec4-b3ed-21e3d3bd269a", userRossini, false ),
                    new FindBySecurityQuestionParameters("887028ea-66fc-41e7-b397-620d7ea6dfbb", 0 ),
                    new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups),
                    new LinkedAccountExistsParameters(userRossini.getKey(), "connObjectKeyValue", "ws-target-resource-timeout", true, linkedAccountsParam, false)
                },
                {
                    new FindKeyParameters("", null, null ),
                    new FindAllParameters(1, 1, 1 ),
                    new FindUsernameParameters("", null, null, null, true),
                    new FindMembershipParameters("", true, null, null),
                    new SecurityChecksParameters(Collections.emptySet(), "", "", Collections.emptyList(), true),
                    new FindByTokenParameters("", null, true ),
                    new FindBySecurityQuestionParameters("", 5 ),
                    new FindAllRolesAndGroupsParameters(null, Collections.emptyList(), true, Collections.emptyList()),
                    new LinkedAccountExistsParameters("", "", "", false, Collections.emptyList(), true)
                },
                {
                    new FindKeyParameters(null, null, null ),
                    new FindAllParameters(2, 3, 2 ),
                    new FindUsernameParameters(null, null, null, null, true ),
                    new FindMembershipParameters(null, true, null, null),
                    new SecurityChecksParameters(Collections.emptySet(), "", "", Collections.emptyList(), true),
                    new FindByTokenParameters(null, null, true ),
                    new FindBySecurityQuestionParameters(null, 5 ),
                    new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups),
                    new LinkedAccountExistsParameters(null, null, null, false, Collections.emptyList(), true)
                },
                {
                    new FindKeyParameters("verd", null, null ),
                    new FindAllParameters(2, 10, 0 ),
                    new FindUsernameParameters("1417acbe-cbf6-4277-9372-e75e04f9700", null, null, null, true ),
                    new FindMembershipParameters("40e409a4-d870-4792-b820-30668f1269b9", false, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "bf825fe1-7320-4a54-bd64-143b5c18ab97"),
                    new SecurityChecksParameters(validAuthRealmsSet, "c9b2dec2-00a7-4855-97c0-d854842b4b24", "c5b75db1-fce7-470f-b780-3b9934d82a9d", validGroupsSet, true),
                    new FindByTokenParameters("1417acbe-cbf6-4277-9372-e75e04f9700", null, true ),
                    new FindBySecurityQuestionParameters("1417acbe-cbf6-4277-9372-e75e04f9700", 5 ),
                    new FindAllRolesAndGroupsParameters(userRossini, rossiniRoles, false, rossiniGroups),
                    new LinkedAccountExistsParameters(userRossini.getKey(), "connObjectKeyValue2", "ws-target-resource-timeout", false, linkedAccountsParam, true)
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

        } catch (NullPointerException e) {
            if (findUsernameParameters.isExpectToThrowException()) {
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
