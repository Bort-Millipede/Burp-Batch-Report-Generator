# Burp Batch Scan Report Generator
![](extender-snapshot.png?raw=true)

Small Burp Suite Extension to generate multiple scan reports by host with just a few clicks. Works with Burp Suite Professional only (can be successfully loaded into Burp Suite Free but will not perform any function).

# Usage
1. Load the burp-batch-scan-report-generator-[VERSION].jar file in the Burp Suite "Extender" tab.
2. When ready to generate reports, navigate to the new "Batch Scan Report Generator" tab.
3. Select the output format for the reports that will be generated (HTML or XML).
4. Select which issue severities to report.
5. Select which issue confidences to report.
6. Select whether to generate reports for all hosts or only hosts set in the Target->Scope tab.
7. Select whether to merge HTTP and HTTPS into one host report, or to have separate reports for both
	1. If the option is selected, one report will be generated for the host that includes findings for HTTP:80 and HTTPS:443. The report filename will be in the following format: ```httphttps__[HOST]-burp.[FORMAT]```.
	2. If the option is selected, Any findings for other ports/protocols on the host will be reported in separate file(s) with the following filename format: ```[PROTOCOL]__[HOST]_[PORT]-burp.[FORMAT]```.
8. Select whether to merge all protocols and ports for a host into one report. The report filename will be in the following format: ```[HOST]_all-burp.[FORMAT]```.
	1. This option automatically sets the "Merge HTTP/HTTPS" option.
9. Select the output directory for the reports by clicking the "Select folder ..." button and selecting a directory. If the selected directory does not yet exist, it will be created when the reports are generated.
10. Select whether to append the date to the report filenames, and choose the desired date from the dropdown box. The report filenames will be in the following format: ```[FILENAME]-[DATE_FORMAT].[FORMAT]```.
	1. The following date formats are available: MMDDYYYY, DDMMYYYY, YYYYMMDD, MMDDYY, DDMMYY, YYMMDD
11. Select whether to save generated reports to sub-directories by host (named after host and created when the reports are generated).
12. Once all options have been set, click the "Generate Report(s)" button to start report generation.
	1. The status of the report generation will be displayed next to the button and will be updated in real time.
	2. A more verbose status of the generation will be printed in the Extender->Output tab for the Extension. This will include a list of the absolute paths to every report file that is successfully generated.
	3. Any errors encountered during report generation will be printed to the Extender->Errors tab for the Extension.

# Building
Requires OpenJDK 17 or higher, and Gradle 8 or higher.

1. Clone the Burp-Batch-Report-Generator repository.
2. Open a terminal and navigate to the Burp-Batch-Report-Generator directory.
3. Issue the following command to compile the extension and create the extension jar file (named Burp-Batch-Report-Generator-[VERSION].jar): ```gradle fatJar```

# Copyright
Copyright (C) 2017, 2022 Jeffrey Cap (Bort_Millipede)

