# Burp Batch Scan Report Generator
![Figure 1-1](extender-snapshot.png?raw=true "")

Small Burp Suite Extension to generate multiple scan reports by host with just a few clicks. Works with Burp Suite Professional only.

#Usage
1. Load the burp-batch-report-generator-[VERSION].jar file in the Burp Suite "Extender" tab.
2. When ready to generate reports, navigate to the new "Batch Scan Report Generator" tab.
3. Select the output format for the reports that will be generated (HTML or XML).
4. Select whether to generate reports for all hosts or only hosts set in the Target->Scope tab.
5. Select whether to merge HTTP and HTTPS into one host report, or to have separate reports for both
	1. If the option is selected, one report will be generated for the host that includes findings for HTTP:80 and HTTPS:443. The report filename will be in the following format: "httphttps__[HOST]-burp.[FORMAT]".
	2. If the option is selected, Any findings for other ports/protocols on the host will be reported in separate file(s) with the following filename format: "[PROTOCOL]__[HOST]_[PORT]-burp.[FORMAT]".
6. Select whether to merge all protocols and ports for a host into one report. The report filename will be in the following format: "[HOST]_all-burp.[FORMAT]".
	1. This option automatically sets the "Merge HTTP/HTTPS" option.
7. Select the output directory for the reports by clicking the "Select folder ..." button and selecting a directory. If the selected directory does not yet exist, it will be created when the reports are generated.
8. Select whether to append the date to the report filenames. The report filenames will be in the following format: "[FILENAME]-MMDDYYYY.[FORMAT]".
9. Once all options have been set, click the "Generate Report(s)" button to start report generation.
	1. The status of the report generation will be displayed next to the button and will be updated in real time.
	2. A more verbose status of the generation will be printed in the Extender->Output tab for the Extension. This will include a list of the absolute paths to every report file that is successfully generated.

# Building
Requires Java Development Kit 7 or higher and Burp Suite Professional jar file.

1. Clone the Burp-Batch-Report-Generator repository.
2. Open a terminal and navigate to the directory containing the Burp-Batch-Report-Generator directory.
3. Create a directory called build in order to store the generated Java .class files.
4. Issue the following command to compile the extension: javac -cp [PATH_TO_BURP_PRO_JAR] -d build Burp-Batch-Report-Generator/burp/BurpExtender.java
5. Issue the following command to create the extension jar file (including the trailing period; named burp-batch-report-generator.jar): jar -vcf burp-burp-batch-report-generator.jar -C build .


Copyright (C) 2017 Jeffrey Cap (Bort_Millipede)
