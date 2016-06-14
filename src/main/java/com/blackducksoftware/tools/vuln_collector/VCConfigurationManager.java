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
package com.blackducksoftware.tools.vuln_collector;

import com.blackducksoftware.tools.commonframework.core.config.ConfigurationManager;

public class VCConfigurationManager extends ConfigurationManager {

    private String projectList;

    private String reportLocation;

    // Current project name (used for spitting out configuration)
    private String projectName;

    private String projectDateCreated;

    // CC related options
    private Boolean includeUnspecifiedVersions = false;

    public VCConfigurationManager(String configFile, Boolean externalInvocation) {
        super(configFile);
        if (!externalInvocation) {
            initLocal();
        }
        includeUnspecifiedVersions = getOptionalProperty(
                VCConstants.INCLUDE_UNSPECIFIED, true, Boolean.class);
    }

    private void initLocal() {
        setProjectList(super.getProperty(VCConstants.PROJECT_LIST));
        setReportLocation(super.getProperty(VCConstants.REPORT_LOCATION));

    }

    public String getProjectList() {
        return projectList;
    }

    public void setProjectList(String projectList) {
        this.projectList = projectList;
    }

    public String getReportLocation() {
        return reportLocation;
    }

    public void setReportLocation(String reportLocation) {
        this.reportLocation = reportLocation;
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getProjectDateCreated() {
        return projectDateCreated;
    }

    public void setProjectDateCreated(String projectDateCreated) {
        this.projectDateCreated = projectDateCreated;
    }

    public Boolean isIncludeUnspecifiedVersions() {
        return includeUnspecifiedVersions;
    }
}
