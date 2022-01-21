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
import lombok.Data;
import lombok.Getter;
import org.apache.syncope.core.persistence.api.dao.SecurityQuestionDAO;
import org.apache.syncope.core.persistence.api.dao.UserDAO;
import org.apache.syncope.core.persistence.api.entity.EntityFactory;
import org.apache.syncope.core.persistence.api.entity.user.SecurityQuestion;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.persistence.jpa.PersistenceTestContext;
import org.junit.Before;
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

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.*;


@RunWith(Parameterized.class)
@ContextConfiguration(classes = { PersistenceTestContext.class })
@Transactional("Master")
public class SecurityQuestionDAOTest {

    @ClassRule
    public static final SpringClassRule src = new SpringClassRule();

    @Rule
    public final SpringMethodRule smr = new SpringMethodRule();

    @Autowired
    private SecurityQuestionDAO securityQuestionDAO;

    @Autowired
    private UserDAO userDAO;

    @Autowired
    private EntityFactory entityFactory;

    @Before
    public void configure() {

    }

    @Parameterized.Parameters
    public static Collection params() {

        SecurityQuestionParam securityQuestionParam = new SecurityQuestionParam("887028ea-66fc-41e7-b397-620d7ea6dfbb", "What's your mother's maiden name?");

        return Arrays.asList(new Object[][]{
                // key: { valid_key, empty, null }
                // minimal test suite for find():
                // [ "887028ea-66fc-41e7-b397-620d7ea6dfbb", "", null ]


                // key: { valid_key, empty, null, existing_key }
                // content: { valid, null }
                // minimal test suite for save():
                // [ { key: "randomUUID()", content: valid },
                // {key: "", content: null },
                // {key: null, content: "" },
                // {key: "887028ea-66fc-41e7-b397-620d7ea6dfbb", valid }
                // ]

                // key: { valid_key, empty, null }

                {
                    new FindParameters(securityQuestionParam.getKey(), securityQuestionParam),
                    new SaveParameters(UUID.randomUUID().toString(), "Test Question?"),
                    new DeleteParameters("887028ea-66fc-41e7-b397-620d7ea6dfbb")
                },
                {
                    new FindParameters("", null),
                    new SaveParameters("", null),
                    new DeleteParameters(""),
                },
                {
                    new FindParameters(null, null),
                    new SaveParameters(null, ""),
                    new DeleteParameters(null)
                },
                {
                    new FindParameters(UUID.randomUUID().toString(), null),
                    new SaveParameters("887028ea-66fc-41e7-b397-620d7ea6dfbb", "Test Question?"),
                    new DeleteParameters(UUID.randomUUID().toString())
                }
        });
    }

    @Parameterized.Parameter(value = 0)
    public FindParameters findParameters;

    @Parameterized.Parameter(value = 1)
    public SaveParameters saveParameters;

    @Parameterized.Parameter(value = 2)
    public DeleteParameters deleteParameters;

    @Test
    public void testFind() {
        SecurityQuestion securityQuestion = securityQuestionDAO.find(findParameters.getKey());
        assertSecurityQuestionEquals(findParameters.getExpectedSecurityQuestion(), securityQuestion);
    }

    @Test
    public void testSave() {
        SecurityQuestion securityQuestion = securityQuestionDAO.find(saveParameters.getKey());
        if (securityQuestion == null) {
            securityQuestion = entityFactory.newEntity(SecurityQuestion.class);
        }
        securityQuestion.setContent(saveParameters.getContent());
        securityQuestion = securityQuestionDAO.save(securityQuestion);
        assertNotNull(securityQuestion);
        assertNotNull(securityQuestion.getKey());
        assertEquals(saveParameters.getContent(), securityQuestion.getContent());
    }

    @Test
    public void testDelete() {
        SecurityQuestion existingSecurityQuestion = securityQuestionDAO.find("887028ea-66fc-41e7-b397-620d7ea6dfbb");
        SecurityQuestion newSecurityQuestion = entityFactory.newEntity(SecurityQuestion.class);
        newSecurityQuestion.setContent("Security Question 1?");
        SecurityQuestion finalSecurityQuestion = securityQuestionDAO.save(newSecurityQuestion);

        // rossini -> "887028ea-66fc-41e7-b397-620d7ea6dfbb", verdi: null, others: new
        userDAO.findAll(0, 100).forEach(u -> {
            if (u.getUsername().equals("rossini") && existingSecurityQuestion != null) {
                u.setSecurityQuestion(existingSecurityQuestion);
                u.setSecurityAnswer("Security Answer 1");
                userDAO.save(u);
            } else if (!u.getUsername().equals("verdi")) {
                u.setSecurityQuestion(finalSecurityQuestion);
                u.setSecurityAnswer("Security Answer 1");
                userDAO.save(u);
            }
        });

        SecurityQuestion securityQuestion = securityQuestionDAO.find(deleteParameters.getKey());
        securityQuestionDAO.delete(deleteParameters.getKey());
        if (securityQuestion != null) {
            List<User> users = userDAO.findBySecurityQuestion(securityQuestion);
            assertEquals(0, users.size());
        }
    }

    private void assertSecurityQuestionEquals(SecurityQuestionParam expectedSecurityQuestion, SecurityQuestion securityQuestion) {
        if (expectedSecurityQuestion == null && securityQuestion == null) {
            assertTrue(true);
        } else if (expectedSecurityQuestion != null && securityQuestion != null) {
            assertEquals(expectedSecurityQuestion.getKey(), securityQuestion.getKey());
            assertEquals(expectedSecurityQuestion.getContent(), securityQuestion.getContent());
        } else {
            fail();
        }
    }


    @AllArgsConstructor
    static class FindParameters {
        @Getter private String key;
        @Getter private SecurityQuestionParam expectedSecurityQuestion;
    }

    @AllArgsConstructor
    static class SaveParameters {
        @Getter private String key;
        @Getter private String content;
    }

    @AllArgsConstructor
    static class DeleteParameters {
        @Getter private String key;
    }

    @AllArgsConstructor
    @Data
    static class SecurityQuestionParam {
        private String key;
        private String content;
    }

}
