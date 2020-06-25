/*
 * Copyright to the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.rioproject.test.monitor;

import net.jini.lookup.ServiceDiscoveryManager;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.rioproject.cybernode.Cybernode;
import org.rioproject.monitor.ProvisionMonitor;
import org.rioproject.impl.opstring.OpString;
import org.rioproject.impl.opstring.OpStringLoader;
import org.rioproject.opstring.OperationalString;
import org.rioproject.opstring.ServiceElement;
import org.rioproject.test.*;
import org.rioproject.test.simple.Simple;
import org.rioproject.test.utils.ArrayUtils;
import org.rioproject.test.utils.CybernodeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.rmi.RemoteException;
import java.text.MessageFormat;
import java.util.Arrays;

/**
 * The class tests the <code>MaxPerMachine</code> capability.
 */
@RunWith (RioTestRunner.class)
@RioTestConfig (
        groups = "MaxPerMachineTestA",
        numLookups = 1,
        numMonitors = 1
)
public class MaxPerMachineTestA {
    private static final Logger logger = LoggerFactory.getLogger(MaxPerMachineTestA.class);
    @SetTestManager
    TestManager testManager;
    private ServiceMonitor<Cybernode> cyberMon;
    private ServiceMonitor<ProvisionMonitor> pmMon;

    /**
     * The service counts fetched before deploying a new OpString.
     */
    int[] prevCounts;

    @Before
    public void setup() throws Exception {
        if(cyberMon==null) {
            final int N = Math.max(testManager.getHostList().size(), 2);
            for (int i = 0; i < N; i++) {
                testManager.startCybernode(i);
            }
            ServiceDiscoveryManager sdm = testManager.getServiceDiscoveryManager();
            pmMon = new ServiceMonitor<>(sdm, ProvisionMonitor.class);
            pmMon.waitFor(1);
            cyberMon = new ServiceMonitor<>(sdm, Cybernode.class);
            cyberMon.waitFor(N);
        }
    }

    @After
    public void cleanup() {
        ProvisionMonitor monitor = pmMon.getServices().get(0);
        TestManager.undeployAll(monitor);
    }

    /**
     * Runs Scenario A, which tests different combinations of provision type,
     * maintain, and max per machine values. Every attempt is preceded by
     * full undeployment.
     *
     * @throws Exception If there are any problems
     */
    @Test
    public void scenarioA() throws Exception {
        final Boolean[] trueFalse = ArrayUtils.asObjects(new boolean[] {false, true});
        final Integer[] maintainValues = ArrayUtils.asObjects(new int[] {1, 5, 10, 20});
        final Integer[] maxPerMachineValues = ArrayUtils.asObjects(new int[] {-1, 0, 1, 5, 10});

        Object[][] combinations = ArrayUtils.combinations(new Object[][] {trueFalse, maintainValues, maxPerMachineValues});
        ProvisionMonitor monitor = pmMon.getServices().get(0);
        for (Object[] combination : combinations) {
            boolean fixed = (Boolean) combination[0];
            int maintain = (Integer) combination[1];
            int maxPerMachine = (Integer) combination[2];
            if (!fixed) {
                maintain = maintain * 2;
            }
            testCombinationA(fixed, maintain, maxPerMachine, monitor);
        }
    }

    /*
     * Tests one combination of Scenario A.
     */
    private void testCombinationA(boolean fixed, int maintain, int maxPerMachine, ProvisionMonitor monitor)
            throws Exception {

        TestManager.undeployAll(monitor);

        // Prepare OpString
        OpStringLoader loader = new OpStringLoader();
        OperationalString[] opstrings =
            loader.parseOperationalString(new File("src/int-test/resources/opstring/simple_opstring.groovy"));
        org.junit.Assert.assertEquals(1, opstrings.length);
        OpString opstring = (OpString)opstrings[0];
        org.junit.Assert.assertEquals(1, opstring.getServices().length);
        ServiceElement service = opstring.getServices()[0];
        service.setPlanned(maintain);
        service.setMaxPerMachine(maxPerMachine);
        service.setProvisionType(fixed? ServiceElement.ProvisionType.FIXED: ServiceElement.ProvisionType.DYNAMIC);

        prevCounts = CybernodeUtils.calcServices(cyberMon.getServices(),Simple.class);
        logger.info("**** Services found before deploying the OpString: {}",
                    Arrays.asList(ArrayUtils.asObjects(prevCounts)));
        logger.debug("Service details: [" + service.getProvisionType() + "]");
        if (maxPerMachine == -1) {
            maxPerMachine = Integer.MAX_VALUE;
        }

        testManager.deploy(opstring, monitor);
        checkStateA(fixed, maintain, maxPerMachine);
    }

    /*
     * Checks that the current state of the system is as expected.
     */
    private void checkStateA(final boolean fixed, final int maintain, final long maxPerMachine) throws Exception {
        // Setup the condition to wait for
        Condition condition = new Condition() {

            public boolean test() {
                int[] counts;
                try {
                    counts = CybernodeUtils.calcServices(cyberMon.getServices(), Simple.class);
                } catch (RemoteException e) {
                    logger.error("Error calculating services", e);
                    return false;
                }
                logger.info("Services found: {}", Arrays.asList(ArrayUtils.asObjects(counts)));

                if (!fixed) { // dynamic
                    long max = maxPerMachine * cyberMon.getServices().size();
                    long expected = Math.min(max, maintain);
                    if (ArrayUtils.sum(counts) != expected) {
                        return false;
                    }
                    for (int count : counts) {
                        if (count > maxPerMachine) {
                            return false;
                        }
                    }
                } else { // fixed
                    long expected = Math.min(maxPerMachine, maintain);
                    for (int count : counts) {
                        if (count != expected) {
                            return false;
                        }
                    }
                }
                return true;
            }

            public String toString() {
                if (!fixed) { // dynamic
                    long max = maxPerMachine * cyberMon.getServices().size();
                    long expected = Math.min(max, maintain);
                    if (maxPerMachine < Integer.MAX_VALUE) {
                        return MessageFormat.format(
                                "# of services == {0} and # of services"
                                        + " on each Cybernode <= {1}",
                                expected,
                                maxPerMachine);
                    } else {
                        return MessageFormat.format(
                                "# of services == {0}",
                                expected);
                    }
                } else { // fixed
                    long expected = Math.min(maxPerMachine, maintain);
                    return MessageFormat.format(
                            "# of services on each Cybernode == {0}",
                            expected);
                }
            }
        };

        Waiter waiter = new Waiter();
        waiter.waitFor(condition);
    }
}
