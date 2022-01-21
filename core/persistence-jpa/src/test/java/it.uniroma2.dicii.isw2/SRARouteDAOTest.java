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
import org.apache.syncope.common.lib.types.SRARouteType;
import org.apache.syncope.core.persistence.api.attrvalue.validation.InvalidEntityException;
import org.apache.syncope.core.persistence.api.dao.SRARouteDAO;
import org.apache.syncope.core.persistence.api.dao.SecurityQuestionDAO;
import org.apache.syncope.core.persistence.api.dao.UserDAO;
import org.apache.syncope.core.persistence.api.entity.EntityFactory;
import org.apache.syncope.core.persistence.api.entity.SRARoute;
import org.apache.syncope.core.persistence.api.entity.user.SecurityQuestion;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.persistence.jpa.PersistenceTestContext;
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

import java.net.URI;
import java.util.*;

import static org.junit.Assert.*;


@RunWith(Parameterized.class)
@ContextConfiguration(classes = { PersistenceTestContext.class })
@Transactional("Master")
public class SRARouteDAOTest {

    @ClassRule
    public static final SpringClassRule src = new SpringClassRule();

    @Rule
    public final SpringMethodRule smr = new SpringMethodRule();

    @Autowired
    private SRARouteDAO sraRouteDAO;

    @Autowired
    private UserDAO userDAO;

    @Autowired
    private EntityFactory entityFactory;

    @Parameterized.Parameters
    public static Collection params() {
        SRARouteParam sraRouteParam = new SRARouteParam("ec7bada2-3dd6-460c-8441-65521d005ffa", "basic1", "http://httpbin.org:80", true, false, SRARouteType.PROTECTED);

        // save
        // name: {valid, null, empty }
        // target: {valid, null, empty }
        // csrf: { true, false }
        // logout: { true, false }
        // type: { "PUBLIC", "PROTECTED", null }
        // if logout == true than type == PROTECTED
        // minimal test suite
        // { name: valid, target: valid, csrf: true, logout: true, type: PUBLIC }
        // { name: null, target: null, csrf: false, logout: false, type: PROTECTED }
        // { name: "", target: "", csrf: true, logout: false, type: null }
        SRARouteParam sraRouteParamSave = new SRARouteParam("", "sraRoute", "http://target.it", true, true, SRARouteType.PUBLIC);
        SRARouteParam sraRouteParamSave2 = new SRARouteParam("", null, null, false, false, SRARouteType.PROTECTED);
        SRARouteParam sraRouteParamSave3 = new SRARouteParam("", "", "", true, false, null);
        SRARouteParam sraRouteParamSave4 = new SRARouteParam("", "sraRoute", "http://target.it", true, true, SRARouteType.PROTECTED);

        return Arrays.asList(new Object[][]{
                {
                    new FindParameters("ec7bada2-3dd6-460c-8441-65521d005ffa", sraRouteParam),
                    new SaveParameters(sraRouteParamSave, true),
                    new DeleteParameters("27c4abc6-717e-432a-bb94-59e4768279ff", 1)
                },
                {
                    new FindParameters("", null),
                    new SaveParameters(sraRouteParamSave2, true),
                    new DeleteParameters("", 0)
                },
                {
                    new FindParameters(null, null),
                    new SaveParameters(sraRouteParamSave3, true),
                    new DeleteParameters(null, 0)
                },
                {
                    new FindParameters(UUID.randomUUID().toString(), null),
                    new SaveParameters(sraRouteParamSave4, false),
                    new DeleteParameters(UUID.randomUUID().toString(), 0)
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
        SRARoute sraRoute = sraRouteDAO.find(findParameters.getKey());
        assertSRARouteEquals(findParameters.getExpectedSRARoute(), sraRoute);
    }

    @Test
    public void testSaveAndDelete() {
        int beforeCount = sraRouteDAO.findAll().size();
        try {
            SRARoute sraRoute = entityFactory.newEntity(SRARoute.class);
            sraRoute.setName(saveParameters.getSraRoute().getName());
            sraRoute.setTarget(URI.create(saveParameters.getSraRoute().getTarget()));
            sraRoute.setCsrf(saveParameters.getSraRoute().isCsrf());
            sraRoute.setLogout(saveParameters.getSraRoute().isLogout());
            sraRoute.setType(saveParameters.getSraRoute().getSraRouteType());
            sraRoute = sraRouteDAO.save(sraRoute);

            if (saveParameters.isExpectToThrowException()) {
                fail();
            } else {
                assertNotNull(sraRoute);
                int afterCount = sraRouteDAO.findAll().size();
                assertEquals(beforeCount + 1, afterCount);

                sraRouteDAO.delete(sraRoute);
                afterCount = sraRouteDAO.findAll().size();
                assertEquals(beforeCount, afterCount);

            }

        } catch (Exception e) {
            if (saveParameters.isExpectToThrowException()) {
                assertTrue(true);
            } else {
                fail();
            }
        }
    }


    @Test
    public void testDelete() {
        int beforeCount = sraRouteDAO.findAll().size();

        sraRouteDAO.delete(deleteParameters.getKey());

        int afterCount = sraRouteDAO.findAll().size();
        assertEquals(beforeCount - deleteParameters.getExpectedDecrement(), afterCount);

    }

    private void assertSRARouteEquals(SRARouteParam expectedSRARoute, SRARoute sraRoute) {
        if (expectedSRARoute == null && sraRoute == null) {
            assertTrue(true);
        } else if (expectedSRARoute != null && sraRoute != null) {
            assertEquals(expectedSRARoute.getKey(), sraRoute.getKey());
            assertEquals(expectedSRARoute.getName(), sraRoute.getName());
            assertEquals(expectedSRARoute.isCsrf(), sraRoute.isCsrf());
            assertEquals(expectedSRARoute.isLogout(), sraRoute.isLogout());
        } else {
            fail();
        }
    }


    @AllArgsConstructor
    static class FindParameters {
        @Getter private String key;
        @Getter private SRARouteParam expectedSRARoute;
    }

    @AllArgsConstructor
    static class SaveParameters {
        @Getter private SRARouteParam sraRoute;
        @Getter private boolean expectToThrowException;
    }

    @AllArgsConstructor
    static class DeleteParameters {
        @Getter private String key;
        @Getter private int expectedDecrement;
    }

    @AllArgsConstructor
    @Data
    static class SRARouteParam {
        private String key;
        private String name;
        private String target;
        private boolean csrf;
        private boolean logout;
        private SRARouteType sraRouteType;

    }

}
