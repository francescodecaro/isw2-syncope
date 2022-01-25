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

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.persistence.api.attrvalue.validation.InvalidEntityException;
import org.apache.syncope.core.persistence.api.dao.*;
import org.apache.syncope.core.persistence.api.entity.AccessToken;
import org.apache.syncope.core.persistence.api.entity.EntityFactory;
import org.apache.syncope.core.persistence.api.entity.Realm;
import org.apache.syncope.core.persistence.api.entity.RelationshipType;
import org.apache.syncope.core.persistence.api.entity.resource.ExternalResource;
import org.apache.syncope.core.persistence.api.entity.user.SecurityQuestion;
import org.apache.syncope.core.persistence.api.entity.user.UMembership;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.persistence.jpa.PersistenceTestContext;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.rules.SpringClassRule;
import org.springframework.test.context.junit4.rules.SpringMethodRule;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityExistsException;
import java.util.*;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
@ContextConfiguration(classes = { PersistenceTestContext.class })
@Transactional("Master")
public class UserDAOSaveTest {

    @ClassRule
    public static final SpringClassRule src = new SpringClassRule();

    @Rule
    public final SpringMethodRule smr = new SpringMethodRule();

    @Autowired
    private UserDAO userDAO;

    @Autowired
    private RealmDAO realmDAO;

    @Autowired
    private SecurityQuestionDAO securityQuestionDAO;

    @Autowired
    private GroupDAO groupDAO;

    @Autowired
    private AccessTokenDAO accessTokenDAO;

    @Autowired
    private ExternalResourceDAO externalResourceDAO;

    @Autowired
    private EntityFactory entityFactory;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Parameterized.Parameters
    public static Collection params() {
        // username: { valid, "", null } OK
        // password: { valid, "", null } OK
        // cipher: { null, each }
        // suspended: { true, false } OK
        // changePwdDate: { valid, null } // present or future? OK
        // securityQuestion: { valid, null, invalid } OK
        // securityAnswer: { valid, "", null } OK
        // failedLogins: >= 0, {0, -1 } OK
        // lastLoginDate: {valid, null } // present or future? OK
        // mustChangePassword: { true, false } OK

        Calendar calendar = Calendar.getInstance();
        calendar.set(2030, 0, 1);
        Date futureDate = calendar.getTime();

        calendar.set(2020, 0, 1);
        Date pastDate = calendar.getTime();

        return Arrays.asList(new Object[][]{
                {
                    new SaveParameters("username", "e4c28e7a-9dbf-4ee7-9441-93812a0d4a28", "password01",
                            "encodedPassword", CipherAlgorithm.SHA,
                            true, new Date(), "887028ea-66fc-41e7-b397-620d7ea6dfbb",
                            "securityAnswer", 0, new Date(),
                            true, true,1, null)
                },
                {
                        new SaveParameters("", "", "",
                                "", CipherAlgorithm.SHA1,
                                false, null, "",
                                "", -1, null,
                                false, false, 0, InvalidEntityException.class)
                },
                {
                        new SaveParameters(null, null,null,
                                null, CipherAlgorithm.SHA256,
                                false, null, null,
                                null, -1, null,
                                false, true, 0, InvalidEntityException.class)
                },
                {
                        new SaveParameters("rossini", "c5b75db1-fce7-470f-b780-3b9934d82a9d", "password",
                                "encodedPassword", CipherAlgorithm.SHA512,
                                false, futureDate, "887028ea-66fc-41e7-b397-620d7ea6dfbb",
                                "securityAnswer", 2, futureDate,
                                false, true, 0, EntityExistsException.class)
                 },
                {
                        new SaveParameters("username2", "c5b75db1-fce7-470f-b780-3b9934d82a9d", "pass",
                                "pass", CipherAlgorithm.AES,
                                false, pastDate, "887028ea-66fc-41e7-b397-620d7ea6dfbb",
                                "securityAnswer", 2, pastDate,
                                false, false, 1, InvalidEntityException.class)
                },
                {
                        new SaveParameters("username3", "c5b75db1-fce7-470f-b780-3b9934d82a9d", "password01",
                                "encodedPassword", CipherAlgorithm.AES,
                                false, new Date(), UUID.randomUUID().toString(),
                                "securityAnswer", 2, new Date(),
                                true, false, 1, null)
                },
                {
                        new SaveParameters("username4", "0679e069-7355-4b20-bd11-a5a0a5453c7c", "password01",
                                "encodedPassword", CipherAlgorithm.SMD5,
                                true, new Date(), "887028ea-66fc-41e7-b397-620d7ea6dfbb",
                                "securityAnswer", 2, new Date(),
                                false, true,1, null)
                },
                {
                        new SaveParameters("username5", "0679e069-7355-4b20-bd11-a5a0a5453c7c", "password01",
                                "encodedPassword", CipherAlgorithm.SSHA,
                                true, new Date(), UUID.randomUUID().toString(),
                                "securityAnswer", 2, new Date(),
                                false, true,1,  null)
                },
                {
                        new SaveParameters("username6", "e4c28e7a-9dbf-4ee7-9441-93812a0d4a28", "password01",
                                "encodedPassword", CipherAlgorithm.SSHA1,
                                true, new Date(), "887028ea-66fc-41e7-b397-620d7ea6dfbb",
                                "securityAnswer", Integer.MAX_VALUE, new Date(),
                                false, true,1,  null)
                },
                {
                        new SaveParameters("username7", "722f3d84-9c2b-4525-8f6e-e4b82c55a36c", "password01",
                                "encodedPassword", CipherAlgorithm.SSHA256,
                                true, new Date(), "887028ea-66fc-41e7-b397-620d7ea6dfbb",
                                "securityAnswer", Integer.MIN_VALUE, new Date(),
                                false, false, 1,  null)
                },
                {
                        new SaveParameters("username8", "722f3d84-9c2b-4525-8f6e-e4b82c55a36c", "password01",
                                "encodedPassword", CipherAlgorithm.SSHA512,
                                true, new Date(), UUID.randomUUID().toString(),
                                "securityAnswer", 0, new Date(),
                                false, false,1,  null)
                },
                {
                        new SaveParameters("username9", "e4c28e7a-9dbf-4ee7-9441-93812a0d4a28","password01",
                                "encodedPassword", CipherAlgorithm.BCRYPT,
                                true, new Date(), "887028ea-66fc-41e7-b397-620d7ea6dfbb",
                                "securityAnswer", 5, new Date(),
                                false, true,1,  null)
                },

        });
    }

    public UserDAOSaveTest(SaveParameters saveParameters) {
        this.saveParameters = saveParameters;
        if (saveParameters.getExpectedException() != null) this.expectedException.expect(saveParameters.getExpectedException());
    }

    public SaveParameters saveParameters;

    @Test
    public void testSave() {
        int beforeCount = userDAO.count();

        User user = entityFactory.newEntity(User.class);
        user.setUsername(saveParameters.getUsername());

        Realm realm = realmDAO.find(saveParameters.getRealmKey());
        user.setRealm(realm);

        user.setPassword(saveParameters.getPassword(), saveParameters.getCipherAlgorithm());
        user.setSuspended(saveParameters.isSuspended());
        user.setChangePwdDate(saveParameters.getChangePwdDate());

        SecurityQuestion securityQuestion = securityQuestionDAO.find(saveParameters.getSecurityQuestionKey());
        user.setSecurityQuestion(securityQuestion);
        user.setSecurityAnswer(saveParameters.getSecurityAnswer());
        user.setFailedLogins(saveParameters.getFailedLogins());
        user.setLastLoginDate(saveParameters.getLastLoginDate());
        user.setMustChangePassword(saveParameters.isMustChangePassword());

        user = userDAO.save(user);

        if (saveParameters.isSaveAccessToken()) {
            AccessToken accessToken = entityFactory.newEntity(AccessToken.class);
            accessToken.setOwner(user.getUsername());
            accessToken.setKey("access-token");
            accessTokenDAO.save(accessToken);
        }


        int afterCount = userDAO.count();
        assertEquals(beforeCount + saveParameters.getExpectedIncrement(), afterCount);

        userDAO.delete(user.getKey());

        User actual = userDAO.find(user.getKey());
        assertNull(actual);

        afterCount = userDAO.count();
        assertEquals(beforeCount, afterCount);
    }

    @AllArgsConstructor
    static class SaveParameters {
        @Getter private String username;
        @Getter private String realmKey;
        @Getter private String password;
        @Getter private String encodedPassword;
        @Getter private CipherAlgorithm cipherAlgorithm;
        @Getter private boolean suspended;
        @Getter private Date changePwdDate;
        @Getter private String securityQuestionKey;
        @Getter private String securityAnswer;
        @Getter private int failedLogins;
        @Getter private Date lastLoginDate;
        @Getter private boolean mustChangePassword;

        @Getter private boolean saveAccessToken;

        @Getter private int expectedIncrement;
        @Getter private Class<? extends Exception> expectedException;
    }
}
