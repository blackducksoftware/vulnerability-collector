# Vulnerability Collector 

## Build

[![Build Status](https://travis-ci.org/blackducksoftware/vulnerability-collector.svg?branch=master)](https://travis-ci.org/blackducksoftware/vulnerability-collector)

## Overview

Summary:
This utility will connect to a Protex project and then use Code Center to collect all related vulnerabilities.  The output is a HTML report.

## Where to download
All releases are available on the GitHub release page: https://github.com/blackducksoftware/vulnerability-collector/releases

### Usage:

Run executable and provide location of configuration file.  An example config file has been included.
An HTML report will be generated within the report output location under the name of the project(s).  

Required parameters:  config [Absolute path of configuration file]

Optional parameters:  projectName  [The name of your Protex project]
Note: This will override the project list in the configuration file

### Example:

VulnCollector config \myfiles\config\vc_config.properties
or
VulnCollector config \myfiles\config\vc_config.properties projectName My_Protex_Project

### Exporting:
In order to use the export features, you must enable your local flash security to allow local files.
http://www.macromedia.com/support/documentation/en/flashplayer/help/settings_manager04.html

### Release Notes:
https://github.com/blackducksoftware/vulnerability-collector/wiki/Release-Notes

## License

Apache License 2.0
