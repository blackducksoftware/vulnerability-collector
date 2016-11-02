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
package com.blackducksoftware.tools.vuln_collector.protex;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import com.blackducksoftware.sdk.fault.SdkFault;
import com.blackducksoftware.sdk.protex.common.ComponentKey;
import com.blackducksoftware.sdk.protex.common.ComponentType;
import com.blackducksoftware.sdk.protex.component.Component;
import com.blackducksoftware.sdk.protex.component.ComponentApi;
import com.blackducksoftware.sdk.protex.project.bom.BomApi;
import com.blackducksoftware.sdk.protex.project.bom.BomComponent;
import com.blackducksoftware.tools.commonframework.core.exception.CommonFrameworkException;
import com.blackducksoftware.tools.commonframework.standard.common.ProjectPojo;
import com.blackducksoftware.tools.commonframework.standard.protex.ProtexProjectPojo;
import com.blackducksoftware.tools.connector.protex.ProtexServerWrapper;
import com.blackducksoftware.tools.vuln_collector.VCConfigurationManager;
import com.blackducksoftware.tools.vuln_collector.VulnerabilityCollectorException;

/**
 * Responsible for connecting and collecting information
 * 
 * @author akamen
 * 
 */
public class VCProtexCollector {

    private Logger log = Logger.getLogger(VCProtexCollector.class);

    private final VCConfigurationManager protexConfig;

    private final ProtexServerWrapper<ProtexProjectPojo> protexWrapper;

    public VCProtexCollector(VCConfigurationManager vcConfig)
            throws CommonFrameworkException {
        protexConfig = vcConfig;
        protexWrapper = initializeConnection();
    }

    /**
     * Use if existing protex connection is established
     * 
     * @param config
     * @param protexWrapper
     * @throws VulnerabilityCollectorException
     */
    public VCProtexCollector(VCConfigurationManager config, ProtexServerWrapper<ProtexProjectPojo> protexWrapper)
            throws VulnerabilityCollectorException {
        if (protexWrapper == null) {
            throw new VulnerabilityCollectorException("Cannot accept empty protex wrapper");
        }
        protexConfig = config;
        this.protexWrapper = protexWrapper;
    }

    private ProtexServerWrapper<ProtexProjectPojo> initializeConnection()
            throws CommonFrameworkException {
        try {
            return new ProtexServerWrapper<ProtexProjectPojo>(protexConfig, true);
        } catch (Exception e) {
            throw new CommonFrameworkException(protexConfig, e.getMessage());
        }

    }

    /**
     * Collects a list of components per project. Components contain information
     * regarding their name/version/key. The key can be used to reference
     * component information later from the KB.
     * 
     * @param projectName
     * @return
     * @throws CommonFrameworkException
     */
    public List<VCProtexComponent> getComponentsForProject(String projectName)
            throws CommonFrameworkException {
        List<VCProtexComponent> compList = new ArrayList<VCProtexComponent>();
        ProjectPojo pojo = protexWrapper.getProjectByName(projectName);
        BomApi bomApi = protexWrapper.getInternalApiWrapper().getBomApi();
        ComponentApi compApi = protexWrapper.getInternalApiWrapper()
                .getComponentApi();

        try {
            List<BomComponent> bomcomponents = bomApi.getBomComponents(pojo
                    .getProjectKey());

            for (BomComponent bomComp : bomcomponents) {
                if (bomComp != null) // Not sure why, but sometimes a null
                // element is inserted into list.
                {
                    ComponentKey key = null;
                    try {
                    	key = bomComp.getComponentKey();
                    	// Need to look up the actual component instead of the
                    	// generic component
                    	Component component = compApi.getComponentByKey(key);
                    	VCProtexComponent vcComponent = new VCProtexComponent(
                    			key);
                    	vcComponent.setCompName(component.getComponentName());
                    	vcComponent.setCompVersion(component.getVersionName());
                    	vcComponent.setCompHomePage(component.getHomePage());
                    	//search only for standard kb components
                    	if( ( component.getComponentType().equals(ComponentType.STANDARD))
                    			||( component.getComponentType().equals(ComponentType.STANDARD_MODIFIED)))
                    	{
                    		vcComponent.setStandard(true);
                    	} else {
                    		vcComponent.setStandard(false);
                    	}
                    	// Add to the list of returned components.

                    	compList.add(vcComponent);
                    } catch (SdkFault e) {
                    	log.warn("Could not get component information for key: "
                    			+ key.getComponentId());
                    }
                }

            }

        } catch (Exception e) {
            throw new CommonFrameworkException(protexConfig,
                    "Unable to get SDK component list: " + e.getMessage());
        }

        return compList;
    }

}
