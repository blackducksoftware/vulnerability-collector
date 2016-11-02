/*******************************************************************************
 * Copyright (C) 2016 Black Duck Software, Inc.
 * http://www.blackducksoftware.com/
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 *  with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 *  under the License.
 *
 *******************************************************************************/
package com.blackducksoftware.tools.vuln_collector.cc;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import com.blackducksoftware.sdk.codecenter.cola.data.KbComponentIdToken;
import com.blackducksoftware.sdk.codecenter.cola.data.KbComponentReleaseIdToken;
import com.blackducksoftware.sdk.codecenter.fault.SdkFault;
import com.blackducksoftware.sdk.codecenter.vulnerability.VulnerabilityApi;
import com.blackducksoftware.sdk.codecenter.vulnerability.data.VulnerabilityPageFilter;
import com.blackducksoftware.sdk.codecenter.vulnerability.data.VulnerabilitySummary;
import com.blackducksoftware.sdk.protex.common.ComponentKey;
import com.blackducksoftware.tools.commonframework.core.exception.CommonFrameworkException;
import com.blackducksoftware.tools.connector.codecenter.CodeCenterServerWrapper;
import com.blackducksoftware.tools.vuln_collector.VCConfigurationManager;
import com.blackducksoftware.tools.vuln_collector.model.ProtexComponentList;
import com.blackducksoftware.tools.vuln_collector.protex.VCProtexComponent;

/**
 * This class connects to Code Center and performs all the business logic
 * associated with vulnerability collection/aggregation
 * 
 * @author akamen
 * 
 */
public class VCCodeCenterCollector {

    private Logger log = Logger.getLogger(VCCodeCenterCollector.class);

    final private VCConfigurationManager vcConfig;

    final private CodeCenterServerWrapper ccWrapper;

    public VCCodeCenterCollector(VCConfigurationManager vcConfig)
            throws CommonFrameworkException {
        this.vcConfig = vcConfig;
        ccWrapper = init();
    }

    private CodeCenterServerWrapper init() throws CommonFrameworkException {
        try {
            return new CodeCenterServerWrapper(vcConfig);
        } catch (Exception e) {
            log.error("Unable to establish Code Center connection: "
                    + e.getMessage());
            throw new CommonFrameworkException(vcConfig, e.getMessage());
        }
    }

    /**
     * For each component looks up the vulnerabilities. For every vulnerability
     * found creates a copy of the protex component.
     * 
     * Determines based on user specifications whether to collect vulns for
     * 'unspecified' versions.
     * 
     * @param protextComponents
     * @return
     * @throws CommonFrameworkException
     */
    public ProtexComponentList populateVulnerabilities(
            List<VCProtexComponent> protexComponents)
            throws CommonFrameworkException {
        ProtexComponentList collectedComponents = new ProtexComponentList();

        try {
            VulnerabilityApi vApi = ccWrapper.getInternalApiWrapper()
                    .getProxy().getVulnerabilityApi();

            VulnerabilityPageFilter filter = new VulnerabilityPageFilter();
            filter.setFirstRowIndex(0);
            filter.setLastRowIndex(Integer.MAX_VALUE);
            filter.setSortAscending(true);

            for (VCProtexComponent protexComponent : protexComponents) {
                // Need to filter out for those situations where unspecified is
                // not wanted
                // If user wants to include unspecified versions...
                if (protexComponent.isVersionSpecified()) {
                    log.info(String
                            .format("Getting vulnerability information for component '%s'",
                                    protexComponent));
                    collectedComponents = collectVulns(protexComponent, vApi,
                            filter, collectedComponents);
                } else {
                    log.debug(String.format(""
                            + "Protex component %s  has unspecified version",
                            protexComponent));

                    if (vcConfig.isIncludeUnspecifiedVersions()) {
                        collectedComponents = collectVulns(protexComponent,
                                vApi, filter, collectedComponents);
                    }
                }

            }
        } catch (SdkFault e) {
            throw new CommonFrameworkException(vcConfig,
                    "Error during vulnerability collection: " + e.getMessage());
        }

        return collectedComponents;

    }

    private ProtexComponentList collectVulns(VCProtexComponent protexComponent,
            VulnerabilityApi vApi, VulnerabilityPageFilter filter,
            ProtexComponentList collectedComponents) throws SdkFault {
        List<VulnerabilitySummary> vulns = 
        		(List<VulnerabilitySummary>) new ArrayList<VulnerabilitySummary>();
        // the search throws an error for custom components (which have no registered vulnerabilities)
        // so we skip non standard components
        if (protexComponent.isStandard()){
        ComponentKey key = protexComponent.getComponentKey();
        
        /**
         * This is unfortunate, but the CC Api forces us into this unpleasant
         * logical switch. The Protex Version ID is mapped to Release ID and
         * since there is not one call for one object we have to create two
         * distinct CC calls.
         */
        if (key.getVersionId() != null) {
            KbComponentReleaseIdToken token = new KbComponentReleaseIdToken();
            token.setId(key.getVersionId());

            vulns = vApi
                    .searchDirectMatchedVulnerabilitiesByKBComponentReleaseId(
                            token, filter);
        } else {
            KbComponentIdToken token = new KbComponentIdToken();
            token.setId(key.getComponentId());

            vulns = vApi.searchDirectMatchedVulnerabilitiesByKBComponentId(
                    token, filter);
        }
        }
        /**
         * Here we create a new protex component for every single vulnerability
         */
        if (vulns.size() > 0) {
            log.info("Adding vulnerabilities for: "
                    + protexComponent.getCompName());
            for (VulnerabilitySummary vulnSummary : vulns) {
                VCProtexComponent copyOfComponent = new VCProtexComponent();
                copyOfComponent.setCompName(protexComponent.getCompName());
                copyOfComponent.setCompHomePage(protexComponent
                        .getCompHomePage());
                copyOfComponent
                        .setCompVersion(protexComponent.getCompVersion());
                copyOfComponent.setComponentKey(protexComponent
                        .getComponentKey());

                copyOfComponent.setVulnSummary(vulnSummary);
                collectedComponents.addComponentToInteralList(copyOfComponent);
            }
        } else {
            // No vulns found, just add the component itself back to the list
            collectedComponents.addComponentToInteralList(protexComponent);
            log.debug(String.format(
                    "No vulnerabilities found for component %s",
                    protexComponent));
        }

        return collectedComponents;
    }
}
