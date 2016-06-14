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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

import com.blackducksoftware.tools.commonframework.core.exception.CommonFrameworkException;
import com.blackducksoftware.tools.vuln_collector.cc.VCCodeCenterCollector;
import com.blackducksoftware.tools.vuln_collector.model.ProtexComponentList;
import com.blackducksoftware.tools.vuln_collector.protex.VCProtexCollector;
import com.blackducksoftware.tools.vuln_collector.protex.VCProtexComponent;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Processes the report by: - Invoking the Protex server - Collecting the BOM -
 * Invoking the Code Center Server - Collecting the vulnerabilities
 * 
 * @author akamen
 * 
 */
public class VCProcessor {

    private Logger log = Logger.getLogger(VCProcessor.class.getClass()
            .getName());

    protected VCConfigurationManager vcConfigManager;

    protected VCCodeCenterCollector vcCCCollector;

    protected VCProtexCollector vcProtexCollector;

    // Optional project name
    private String[] userProvidedList;

    protected File reportLocation;

    final private static String WEB_RESOURCE = "web";

    final private static String JSON_DATA_DIRECTORY = "jsondata";

    /**
     * Initializes the Vulnerability Collector by consuming a VC property file
     * 
     * @param configLocation
     *            - Location of configuration file
     * @param projectNameList
     *            - List of Protex projects (at least one required)
     * @throws Exception
     */
    public VCProcessor(String configLocation, String[] projectNameList)
            throws Exception {
        userProvidedList = projectNameList;
        vcConfigManager = new VCConfigurationManager(configLocation, false);

        vcCCCollector = new VCCodeCenterCollector(vcConfigManager);
        vcProtexCollector = new VCProtexCollector(vcConfigManager);

        reportLocation = getReportLocation();
        // If the user list is empty, use the configuration file
        try {
            if (userProvidedList == null) {
                userProvidedList = getProjectList(vcConfigManager
                        .getProjectList());
            }
        } catch (Exception e) {
            throw new Exception("Unable to parse project list");
        }
    }

    /**
     * Empty constructor
     */
    public VCProcessor() {
        vcProtexCollector = null;
        vcConfigManager = null;
        vcCCCollector = null;
        reportLocation = null;
    }

    /**
     * Processes the report by collecting all the Protex/CC data and writing out the
     * serialized arrays into JSON
     * 
     * @throws Exception
     */
    public void processReport() throws Exception {
        log.info("List of projects to process: " + userProvidedList.length);
        for (String project : userProvidedList) {
            log.info("Processing for project: " + project);

            // Set the config options for javascript reading
            vcConfigManager.setProjectName(project);

            Date d = Calendar.getInstance().getTime();

            DateFormat df = new SimpleDateFormat("MM/dd/yyyy");

            vcConfigManager.setProjectDateCreated(df.format(d));

            File reportLocationSubDir = prepareSubDirectory(reportLocation,
                    project);

            ProtexComponentList protexComponentList = getComponentVulnerabilities(project);

            try {
                // Transform to JSON
                writeOutJsonFile(reportLocationSubDir,
                        protexComponentList.getVersionList(),
                        "json_expanded.js", "vcData");
                if (vcConfigManager.isIncludeUnspecifiedVersions()) {
                    writeOutJsonFile(reportLocationSubDir,
                            protexComponentList.getUnspecifiedList(),
                            "json_expanded_unspecified.js", "vcDataNoVersions");
                }

                // Spit out configuration file
                writeOutJsonFile(reportLocationSubDir, vcConfigManager,
                        "json_config.js", "configData");
                log.info(String.format(
                        "Finished writing data for project {%s}", project));

            } catch (Exception e) {
                throw new Exception("Error during JSON transformation", e);
            }
        }
    }

    /**
     * Used by the main process method, but can also be called externally.
     * 
     * @param project
     * @return
     * @throws Exception
     */
    protected ProtexComponentList getComponentVulnerabilities(String project) throws VulnerabilityCollectorException {
        // Grab all the Protex components
        List<VCProtexComponent> fullMasterList = null;
        ProtexComponentList protexComponentList = null;
        try {

            fullMasterList = vcProtexCollector
                    .getComponentsForProject(project);
            log.info("Found protex components: " + fullMasterList.size());
        } catch (Exception e) {
            log.error("Fatal error during Protex connectivity: "
                    + e.getMessage());
            throw new VulnerabilityCollectorException("Fatal", e);
        }
        // Populate the list with Code Center vulnerability information
        try {
            protexComponentList = vcCCCollector
                    .populateVulnerabilities(fullMasterList);

        } catch (Exception e) {
            log.error("Fatal error during Code Center connectivity: "
                    + e.getMessage());
            throw new VulnerabilityCollectorException("Fatal", e);
        }

        return protexComponentList;
    }

    private void writeOutJsonFile(File reportLocationSubDir, Object object,
            String fileName, String arrayName) throws IOException {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        File jsonFile = new File(reportLocationSubDir + File.separator
                + JSON_DATA_DIRECTORY + File.separator + fileName);
        log.info("Writing out JSON output to: " + jsonFile);

        FileWriter writer = new FileWriter(jsonFile);

        // Here we want to assign the json data to an array so that we can
        // reference it in our javascript later on.
        String jsonData = gson.toJson(object);
        String jsonDataWrapped = arrayName + " = " + jsonData;
        writer.write(jsonDataWrapped);
        writer.close();

        log.info(String.format("Finished writing to location {%s}", jsonFile));
    }

    public static String[] getProjectList(String projectListString)
            throws Exception {
        String[] projects = projectListString.split(",");

        if (projects.length == 0) {
            throw new Exception(
                    "Unable to determine project list, please provide comma separated list");
        }

        return projects;

    }

    /**
     * Creates a directory using the project name Parses the name to escape
     * offensive characters.
     * 
     * @param reportLocation
     * @param project
     * @return
     * @throws Exception
     */
    private File prepareSubDirectory(File reportLocation, String project)
            throws Exception {
        project = formatProjectPath(project);
        File reportLocationSubDir = new File(reportLocation.toString()
                + File.separator + project);
        if (!reportLocationSubDir.exists()) {
            boolean dirsMade = reportLocationSubDir.mkdirs();
            if (!dirsMade) {
                throw new Exception(
                        "Unable to create report sub-directory for project: "
                                + project);
            }
        }

        // Copy the web resources into this new location
        ClassLoader classLoader = getClass().getClassLoader();
        File webresources = new File(classLoader.getResource(WEB_RESOURCE)
                .getFile());

        if (!webresources.exists()) {
            throw new Exception(
                    "Fatal exception, internal web resources are missing!");
        }

        File[] webSubDirs = webresources.listFiles();
        if (webSubDirs.length == 0) {
            throw new Exception(
                    "Fatal exception, internal web resources sub directories are missing!  Corrupt archive.");
        }

        boolean readable = webresources.setReadable(true);
        if (!readable) {
            throw new Exception(
                    "Fatal. Cannot read internal web resource directory!");
        }

        try {
            for (File webSubDir : webSubDirs) {
                if (webSubDir.isDirectory()) {
                    FileUtils.copyDirectoryToDirectory(webSubDir,
                            reportLocationSubDir);
                } else {
                    FileUtils.copyFileToDirectory(webSubDir,
                            reportLocationSubDir);
                }
            }
        } catch (IOException ioe) {
            throw new Exception("Error during creation of report directory",
                    ioe);
        }

        return reportLocationSubDir;
    }

    /**
     * Grabs the user specified location for reports
     * 
     * @return
     * @throws CommonFrameworkException
     */
    private File getReportLocation() throws CommonFrameworkException {
        String reportLocation = vcConfigManager.getReportLocation();
        if (reportLocation == null) {
            throw new CommonFrameworkException(vcConfigManager,
                    "Report location not specified");
        }

        File f = new File(reportLocation);
        if (!f.exists()) {
            throw new CommonFrameworkException(vcConfigManager, String.format(
                    "Report location {%s} does not exist", reportLocation));
        }

        if (!f.canWrite()) {
            throw new CommonFrameworkException(vcConfigManager, String.format(
                    "Report location {%s} has no write access", reportLocation));
        }

        return f;
    }

    private String formatProjectPath(String name) {
        if (name == null) {
            return name;
        }

        name = name.replaceAll("\"", "");
        name = name.replaceAll("#", "_");
        name = name.trim();

        return name;
    }

}
