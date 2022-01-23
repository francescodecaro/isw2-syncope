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

import org.apache.syncope.core.persistence.api.dao.ApplicationDAO;
import org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO;
import org.apache.syncope.core.persistence.api.dao.UserDAO;
import org.apache.syncope.core.persistence.api.entity.resource.ExternalResource;
import org.apache.syncope.core.persistence.api.entity.user.LinkedAccount;
import org.apache.syncope.core.persistence.jpa.PersistenceTestContext;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { PersistenceTestContext.class })
@Transactional("Master")
public class UserDAOTest2 {

    @Autowired
    private UserDAO userDAO;

    @Autowired
    private ApplicationDAO applicationDAO;

    @Autowired
    private ExternalResourceDAO externalResourceDAO;

    @Test
    public void testCount() {
        assertEquals(5, userDAO.count());
    }

    @Test
    public void testCountByRealm() {
        Map<String, Integer> countByRealm = userDAO.countByRealm();
        Map<String, Integer> expected = new HashMap<>();
        expected.put("/even", 1);
        expected.put("/", 4);

        assertEquals(expected.size(), countByRealm.size());
        assertEquals(expected.keySet(), countByRealm.keySet());
        countByRealm.forEach((k, v) -> {
            assertEquals(expected.get(k), v);
        });
    }

    @Test
    public void testCountByStatus() {
        Map<String, Integer> countByStatus = userDAO.countByStatus();
        Map<String, Integer> expected = new HashMap<>();
        expected.put("active", 5);

        assertEquals(expected.size(), countByStatus.size());
        assertEquals(expected.keySet(), countByStatus.keySet());
        countByStatus.forEach((k, v) -> {
            assertEquals(expected.get(k), v);
        });
    }


    @Test
    public void testFindLinkedAccount() {
        List<LinkedAccount> linkedAccounts = userDAO.findLinkedAccountsByPrivilege(applicationDAO.findPrivilege("postMighty"));
        assertEquals(1, linkedAccounts.size());

        ExternalResource externalResource = externalResourceDAO.find("ws-target-resource-timeout");
        linkedAccounts = userDAO.findLinkedAccountsByResource(externalResource);
        assertEquals(1, linkedAccounts.size());
    }

}
