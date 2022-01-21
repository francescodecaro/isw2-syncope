package it.uniroma2.dicii.isw2;

import org.apache.syncope.common.lib.types.SRARouteType;
import org.apache.syncope.core.persistence.api.dao.SRARouteDAO;
import org.apache.syncope.core.persistence.api.entity.SRARoute;
import org.apache.syncope.core.persistence.jpa.PersistenceTestContext;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { PersistenceTestContext.class })
@Transactional("Master")
public class SRARouteDAOTest2 {

    @Autowired
    private SRARouteDAO sraRouteDAO;

    @Test
    public void findAllTest() {
        List<SRARoute> sraRoute = sraRouteDAO.findAll();
        assertNotNull(sraRoute);
        assertEquals(2, sraRoute.size());
    }
}
