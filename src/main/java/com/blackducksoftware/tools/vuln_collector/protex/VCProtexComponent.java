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

import com.blackducksoftware.sdk.codecenter.vulnerability.data.VulnerabilitySummary;
import com.blackducksoftware.sdk.protex.common.ComponentKey;

/**
 * Bean holding component information
 * 
 * @author akamen
 * 
 */
public class VCProtexComponent {

    private String compName;
    private String compVersion;
    private String compHomePage;
    private VulnerabilitySummary vulnSummary;
    private ComponentKey componentKey;
    private Boolean isVersionSpecified = true;
	private boolean isStandard;

    public VCProtexComponent() {
    }

    public VCProtexComponent(ComponentKey cKey) {
	this.setComponentKey(cKey);
    }


    public String getCompName() {
	return compName;
    }

    public void setCompName(String compName) {
	this.compName = compName;
    }

    public String getCompVersion() {
	return compVersion;
    }

    /**
     * Checks to see if version name matches a magic string 'unspecified'
     * 
     * @param compVersion
     */
    public void setCompVersion(String compVersion) {
	this.compVersion = compVersion;
	if (compVersion == null)
	    this.setIsVersionSpecified(false);
	else {
	    if (compVersion.equalsIgnoreCase("unspecified"))
		this.setIsVersionSpecified(false);
	}
    }

    public String getCompHomePage() {
	return compHomePage;
    }

    public void setCompHomePage(String compHomePage) {
	this.compHomePage = compHomePage;
    }

    public ComponentKey getComponentKey() {
	return componentKey;
    }

    public void setComponentKey(ComponentKey componentKey) {
	this.componentKey = componentKey;
    }

    public Boolean isVersionSpecified() {
	return isVersionSpecified;
    }

    private void setIsVersionSpecified(Boolean isVersionSpecified) {
	this.isVersionSpecified = isVersionSpecified;
    }

    public String toString() {
	return "Name: " + this.compName + " Version: " + this.compVersion;
    }

    public VulnerabilitySummary getVulnSummary() {
	return vulnSummary;
    }

    public void setVulnSummary(VulnerabilitySummary vulnSummary) {
	this.vulnSummary = vulnSummary;
    }

	public boolean isStandard() {
		return isStandard;
	}

	public void setStandard(boolean isStandard) {
		this.isStandard = isStandard;
	}

}
