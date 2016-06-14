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
/**
 * 
 */
package com.blackducksoftware.tools.vuln_collector;

import com.blackducksoftware.tools.commonframework.core.exception.CommonFrameworkException;
import com.blackducksoftware.tools.commonframework.standard.protex.ProtexProjectPojo;
import com.blackducksoftware.tools.connector.protex.ProtexServerWrapper;
import com.blackducksoftware.tools.vuln_collector.cc.VCCodeCenterCollector;
import com.blackducksoftware.tools.vuln_collector.model.ProtexComponentList;
import com.blackducksoftware.tools.vuln_collector.protex.VCProtexCollector;

/**
 * External hook for the vulnerability collector, use this class if invoking this utility
 * as a dependency
 * 
 * @author akamen
 * 
 */
public class VCProcessorExternal extends VCProcessor {

    /**
     * Constructor used for externally invoking the vulnerability collector
     * 
     * @param configLocation
     * @throws CommonFrameworkException
     */
    public VCProcessorExternal(String configLocation)
            throws CommonFrameworkException {
        super();
        vcConfigManager = new VCConfigurationManager(configLocation, true);

        vcCCCollector = new VCCodeCenterCollector(vcConfigManager);
        vcProtexCollector = new VCProtexCollector(vcConfigManager);
        // This constructor does not require a report location.
        reportLocation = null;
    }

    /**
     * Use this constructor for external invocation with a ready-made protex wrapper.
     * 
     * @param configLocation
     * @throws CommonFrameworkException
     */
    public VCProcessorExternal(String configLocation, ProtexServerWrapper<ProtexProjectPojo> psw)
            throws CommonFrameworkException, VulnerabilityCollectorException {
        super();
        vcConfigManager = new VCConfigurationManager(configLocation, true);

        vcCCCollector = new VCCodeCenterCollector(vcConfigManager);
        vcProtexCollector = new VCProtexCollector(vcConfigManager, psw);

        // This constructor does not require a report location.
        reportLocation = null;
    }

    /**
     * Returns all vulnerabilities for components with a specified Protex project
     */
    @Override
    public ProtexComponentList getComponentVulnerabilities(String project) throws VulnerabilityCollectorException
    {
        return super.getComponentVulnerabilities(project);
    }
}
