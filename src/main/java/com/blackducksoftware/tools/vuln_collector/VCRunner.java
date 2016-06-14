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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;

/**
 * Main entry point for the vulnerability connector. Expects a configuration
 * file location as a runtime parameter.
 * 
 * @author akamen
 * 
 */
public class VCRunner {
    private static Logger log = Logger.getLogger(VCRunner.class.getClass()
	    .getName());
    private static Options options = new Options();

    private static String TITLE = "Vulnerability Collector";

    public static void main(String[] args) throws Exception {
	System.out.println(TITLE);
	CommandLineParser parser = new DefaultParser();

	options.addOption("h", "help", false, "show help.");

	Option projectNameOption = new Option("projectName", true,
		"Name of Project (optional)");
	projectNameOption.setRequired(false);
	options.addOption(projectNameOption);

	Option configFileOption = new Option("config", true,
		"Location of configuration file (required)");
	configFileOption.setRequired(true);
	options.addOption(configFileOption);

	try {

	    CommandLine cmd = parser.parse(options, args);

	    if (cmd.hasOption("h"))
		help();

	    String[] projectNameList = null;
	    File configFile = null;

	    if (cmd.hasOption(VCConstants.CL_PROJECT_NAME)) {
		String projectName = cmd
			.getOptionValue(VCConstants.CL_PROJECT_NAME);
		log.info("Project name: " + projectName);
		// Could be a single project or comma delim
		projectNameList = VCProcessor.getProjectList(projectName);
	    }

	    // Config File
	    if (cmd.hasOption(VCConstants.CL_CONFIG)) {
		String configFilePath = cmd
			.getOptionValue(VCConstants.CL_CONFIG);
		log.info("Config file location: " + configFilePath);
		configFile = new File(configFilePath);
		if (!configFile.exists()) {
		    log.error("Configuration file does not exist at location: "
			    + configFile);
		    System.exit(-1);
		}
	    } else {
		log.error("Must specify configuration file!");
		help();
	    }

	    VCProcessor processor = new VCProcessor(configFile.toString(),
		    projectNameList);
	    processor.processReport();

	} catch (ParseException e) {
	    log.error("Error parsing: " + e.getMessage());
	    help();
	} catch (Exception e) {
	    log.error("General error: " + e.getMessage());

	}

    }

    private static void help() {
	HelpFormatter formater = new HelpFormatter();
	formater.printHelp(TITLE, options);
	System.exit(0);
    }
}
