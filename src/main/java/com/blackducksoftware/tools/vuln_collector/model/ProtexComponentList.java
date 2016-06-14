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
package com.blackducksoftware.tools.vuln_collector.model;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import com.blackducksoftware.tools.vuln_collector.protex.VCProtexComponent;

/**
 * The main bean representing the list of all components, split up by their
 * distinct version behavior
 * 
 * @author akamen
 * 
 */
public class ProtexComponentList {

    private Logger log = Logger.getLogger(ProtexComponentList.class);

    private final List<VCProtexComponent> versionList = new ArrayList<VCProtexComponent>();
    private final List<VCProtexComponent> unspecifiedList = new ArrayList<VCProtexComponent>();

    public ProtexComponentList() {
    }

    public List<VCProtexComponent> getVersionList() {
	return versionList;
    }

    public List<VCProtexComponent> getUnspecifiedList() {
	return unspecifiedList;
    }

    private void addToVersionList(VCProtexComponent versionComp) {
	versionList.add(versionComp);
    }

    private void addToUnspecifiedList(VCProtexComponent unspecifiedComp) {
	unspecifiedList.add(unspecifiedComp);
    }

    /**
     * Adds the protex component to the appropriate list depending on the
     * version specifications
     * 
     * @param unspecifiedComp
     */
    public void addComponentToInteralList(VCProtexComponent component) {
	if (component.isVersionSpecified()) {
	    log.debug(String.format("Adding version component %s", component));
	    addToVersionList(component);
	} else {
	    log.debug(String.format("Adding unspecified component %s",
		    component));
	    addToUnspecifiedList(component);
	}
    }

}
