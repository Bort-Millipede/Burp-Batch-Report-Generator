/*
	BurpExtender.java
	
	v0.3 (6/XX/2022)
	
	Small Burp Suite Extension to generate multiple scan reports by host with just a few clicks. Works with Burp Suite Professional only.
*/

package burp;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JLabel;
import javax.swing.ButtonGroup;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JButton;
import javax.swing.SwingConstants;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.FlowLayout;
import java.awt.Color;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.io.File;
import java.util.Hashtable;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.Iterator;
import java.util.Date;
import java.net.URL;
import java.text.SimpleDateFormat;

public class BurpExtender implements IBurpExtender,ITab,ActionListener {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private String name;
	
	//configuration fields
	private String reportFormat;
	private boolean[] severities; //filters for issue severities
	private boolean[] confidences; //filters for issue confidences
	private boolean inscopeOnly;
	private boolean mergeHttps; //merge http:80 and https:443 into one report
	private boolean mergeAll; //merge all protocols and ports into 1 report
	private File destDir;
	private boolean fileDate; //append generation date to filename in format MMDDYYYY
	private boolean createSubDirectories; //create sub-directory for each report (named after host)
	
	//UI fields
	private JPanel component;
	private JRadioButton htmlButton;
	private JRadioButton xmlButton;
	private JCheckBox includeHighSeverityCheck;
	private JCheckBox includeMediumSeverityCheck;
	private JCheckBox includeLowSeverityCheck;
	private JCheckBox includeInformationSeverityCheck;
	private JCheckBox includeFalsePositiveSeverityCheck;
	private JCheckBox includeCertainConfidenceCheck;
	private JCheckBox includeFirmConfidenceCheck;
	private JCheckBox includeTentativeConfidenceCheck;
	private JCheckBox inscopeCheck;
	private JCheckBox httpsCheck;
	private JCheckBox mergeAllCheck;
	private JFileChooser destDirChooser;
	private JButton destDirButton;
	private JLabel destDirLabel;
	private JCheckBox filenameDateCheck;
	private JComboBox<String> dateFormatChooser;
	private JCheckBox createSubDirectoriesCheck;
	private JButton generateButton;
	private JLabel statusLabel;
	
	//constants
	private static final String VERSION = "0.3";
	private static final String[] dateFormats = {"MMddyyyy","ddMMyyyy","yyyyMMdd","MMddyy","ddMMyy","yyMMdd"};
	
	//IBurpExtender methods
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks cb) {
		callbacks = cb;
		helpers = callbacks.getHelpers();
		name = "Batch Scan Report Generator";
		callbacks.setExtensionName(name+" v"+VERSION);
		
		//initialized default settings
		reportFormat = "HTML";
		severities = new boolean[] {true,true,true,true,false};
		confidences = new boolean[] {true,true,true};
		inscopeOnly = true;
		mergeHttps = true;
		mergeAll = false;
		destDir = new File(System.getProperty("java.io.tmpdir"));
		fileDate = false;
		createSubDirectories = false;
		
		callbacks.addSuiteTab(this);
	}
	
	
	//ITab methods
	@Override
	public String getTabCaption() {
		return name;
	}
	
	@Override
	public Component getUiComponent() {
		component = new JPanel();
		
		JPanel innerPanel = new JPanel(new GridLayout(10,2,2,0));
		innerPanel.add(new JLabel("Report Output Format:",SwingConstants.RIGHT));
		htmlButton = new JRadioButton("HTML",true);
		htmlButton.addActionListener(this);
		htmlButton.setActionCommand("HTML");
		xmlButton = new JRadioButton("XML",false);
		xmlButton.addActionListener(this);
		xmlButton.setActionCommand("XML");
		ButtonGroup bg = new ButtonGroup();
		bg.add(htmlButton);
		bg.add(xmlButton);
		JPanel buttonPanel = new JPanel(new GridLayout(2,1));
		buttonPanel.add(htmlButton);
		buttonPanel.add(xmlButton);
		innerPanel.add(buttonPanel);
		innerPanel.add(new JLabel("Issue Severities To Include:",SwingConstants.RIGHT));
		JPanel severitiesPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		includeHighSeverityCheck = new JCheckBox((String) "High",true);
		includeHighSeverityCheck.addActionListener(this);
		includeMediumSeverityCheck = new JCheckBox((String) "Medium",true);
		includeMediumSeverityCheck.addActionListener(this);
		includeLowSeverityCheck = new JCheckBox((String) "Low",true);
		includeLowSeverityCheck.addActionListener(this);
		includeInformationSeverityCheck = new JCheckBox((String) "Information",true);
		includeInformationSeverityCheck.addActionListener(this);
		includeFalsePositiveSeverityCheck = new JCheckBox((String) "False positive",false);
		includeFalsePositiveSeverityCheck.addActionListener(this);
		severitiesPanel.add(includeHighSeverityCheck);
		severitiesPanel.add(includeMediumSeverityCheck);
		severitiesPanel.add(includeLowSeverityCheck);
		severitiesPanel.add(includeInformationSeverityCheck);
		severitiesPanel.add(includeFalsePositiveSeverityCheck);
		innerPanel.add(severitiesPanel);
		innerPanel.add(new JLabel("Issue Confidences To Include:",SwingConstants.RIGHT));
		JPanel confidencesPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		includeCertainConfidenceCheck = new JCheckBox((String) "Certain",true);
		includeCertainConfidenceCheck.addActionListener(this);
		includeFirmConfidenceCheck = new JCheckBox((String) "Firm",true);
		includeFirmConfidenceCheck.addActionListener(this);
		includeTentativeConfidenceCheck = new JCheckBox((String) "Tentative",true);
		includeTentativeConfidenceCheck.addActionListener(this);
		confidencesPanel.add(includeCertainConfidenceCheck);
		confidencesPanel.add(includeFirmConfidenceCheck);
		confidencesPanel.add(includeTentativeConfidenceCheck);
		innerPanel.add(confidencesPanel);
		innerPanel.add(new JLabel("Report On In-Scope Sites Only:",SwingConstants.RIGHT));
		inscopeCheck = new JCheckBox((String) null,true);
		inscopeCheck.addActionListener(this);
		innerPanel.add(inscopeCheck);
		innerPanel.add(new JLabel("Merge HTTP (port 80) and HTTPS (port 443) For Reports:",SwingConstants.RIGHT));
		httpsCheck = new JCheckBox((String) null,true);
		httpsCheck.addActionListener(this);
		innerPanel.add(httpsCheck);
		innerPanel.add(new JLabel("One Host Per Report (Combine All Protocols and Ports):",SwingConstants.RIGHT));
		mergeAllCheck = new JCheckBox((String) null,false);
		mergeAllCheck.addActionListener(this);
		innerPanel.add(mergeAllCheck);
		innerPanel.add(new JLabel("Report Output Root Directory:",SwingConstants.RIGHT));
		destDirChooser = new JFileChooser();
		destDirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		JPanel dirPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		destDirButton = new JButton("Select folder ...");
		destDirButton.addActionListener(this);
		destDirLabel = new JLabel(destDir.getAbsolutePath());
		dirPanel.add(destDirButton);
		dirPanel.add(destDirLabel);
		innerPanel.add(dirPanel);
		innerPanel.add(new JLabel("Append Date To Report Filenames:",SwingConstants.RIGHT));
		JPanel datePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		filenameDateCheck = new JCheckBox("Date Format:",false);
		filenameDateCheck.addActionListener(this);
		datePanel.add(filenameDateCheck);
		dateFormatChooser = new JComboBox<String>();
		for(int i=0;i<dateFormats.length;i++) {
			dateFormatChooser.addItem(dateFormats[i].toUpperCase());
		}
		dateFormatChooser.setEnabled(false);
		datePanel.add(dateFormatChooser);
		innerPanel.add(datePanel);
		innerPanel.add(new JLabel("Save Reports To Sub-Directories By Host (Named After Host):",SwingConstants.RIGHT));
		createSubDirectoriesCheck = new JCheckBox((String) null,false);
		createSubDirectoriesCheck.addActionListener(this);
		innerPanel.add(createSubDirectoriesCheck);
		generateButton = new JButton("Generate Report(s)");
		generateButton.addActionListener(this);
		innerPanel.add(generateButton);
		statusLabel = new JLabel();
		statusLabel.setForeground(Color.ORANGE);
		innerPanel.add(statusLabel);
		component.add(innerPanel);
		callbacks.customizeUiComponent(component);
		return new JScrollPane(component);
	}
	
	
	//ActionListener methods
	@Override
	public void actionPerformed(ActionEvent ae) {
		Object source = ae.getSource();
		if((source == htmlButton) || (source == xmlButton)) {
			String comStr = ae.getActionCommand();
			if(comStr.equalsIgnoreCase("HTML")) {
				reportFormat = "HTML".toUpperCase();
			} else if(comStr.equalsIgnoreCase("XML")) {
				reportFormat = "XML".toUpperCase();
			}
		} else if(source == includeHighSeverityCheck) {
			JCheckBox jcb = (JCheckBox) source;
			severities[0] = jcb.isSelected();
		} else if(source == includeMediumSeverityCheck) {
			JCheckBox jcb = (JCheckBox) source;
			severities[1] = jcb.isSelected();
		} else if(source == includeLowSeverityCheck) {
			JCheckBox jcb = (JCheckBox) source;
			severities[2] = jcb.isSelected();
		} else if(source == includeInformationSeverityCheck) {
			JCheckBox jcb = (JCheckBox) source;
			severities[3] = jcb.isSelected();
		} else if(source == includeFalsePositiveSeverityCheck) {
			JCheckBox jcb = (JCheckBox) source;
			severities[4] = jcb.isSelected();
		} else if(source == includeCertainConfidenceCheck) {
			JCheckBox jcb = (JCheckBox) source;
			confidences[0] = jcb.isSelected();
		} else if(source == includeFirmConfidenceCheck) {
			JCheckBox jcb = (JCheckBox) source;
			confidences[1] = jcb.isSelected();
		} else if(source == includeTentativeConfidenceCheck) {
			JCheckBox jcb = (JCheckBox) source;
			confidences[2] = jcb.isSelected();
		} else if(source == inscopeCheck) {
			JCheckBox jcb = (JCheckBox) source;
			inscopeOnly = jcb.isSelected();
		} else if(source == httpsCheck) {
			JCheckBox jcb = (JCheckBox) source;
			mergeHttps = jcb.isSelected();
		} else if(source == mergeAllCheck) {
			JCheckBox jcb = (JCheckBox) source;
			mergeAll = jcb.isSelected();
			if(mergeAll) {
				httpsCheck.setSelected(true);
				httpsCheck.setEnabled(false);
			} else {
				httpsCheck.setSelected(mergeHttps);
				httpsCheck.setEnabled(true);
			}
		} else if(source == destDirButton) {
			int res = destDirChooser.showOpenDialog(null);
			if(res == JFileChooser.APPROVE_OPTION) {
				destDir = destDirChooser.getSelectedFile();
				destDirLabel.setText(destDir.getAbsolutePath());
			}
		} else if(source == filenameDateCheck) {
			JCheckBox jcb = (JCheckBox) source;
			fileDate = jcb.isSelected();
			dateFormatChooser.setEnabled(fileDate);
		} else if(source == createSubDirectoriesCheck) {
			JCheckBox jcb = (JCheckBox) source;
			createSubDirectories = jcb.isSelected();
		} else if(source == generateButton) {
			Thread genThread = new Thread(new GenerateThread());
			genThread.start();
		}
	}
	
	
	//private "Report Generation Thread" class
	private class GenerateThread implements Runnable {
		@Override
		public void run() {
			generateButton.setText("Generating Report(s), Please Wait...");
			generateButton.setEnabled(false);
			htmlButton.setEnabled(false);
			xmlButton.setEnabled(false);
			includeHighSeverityCheck.setEnabled(false);
			includeMediumSeverityCheck.setEnabled(false);
			includeLowSeverityCheck.setEnabled(false);
			includeInformationSeverityCheck.setEnabled(false);
			includeFalsePositiveSeverityCheck.setEnabled(false);
			includeCertainConfidenceCheck.setEnabled(false);
			includeFirmConfidenceCheck.setEnabled(false);
			includeTentativeConfidenceCheck.setEnabled(false);
			inscopeCheck.setEnabled(false);
			httpsCheck.setEnabled(false);
			mergeAllCheck.setEnabled(false);
			destDirButton.setEnabled(false);
			filenameDateCheck.setEnabled(false);
			dateFormatChooser.setEnabled(false);
			createSubDirectoriesCheck.setEnabled(false);
			callbacks.printOutput("Reading Full List of Issues");
			statusLabel.setText("Reading Full List of Issues...");
			
			IScanIssue[] issueListFull = callbacks.getScanIssues(null);
			if(issueListFull==null) issueListFull = new IScanIssue[0]; //if extension is loaded into Burp Suite Free: avoid NullPointerException here
			Hashtable<String,ArrayList<String>> sitesDict = new Hashtable<String,ArrayList<String>>();
			Set<String> siteKeys = sitesDict.keySet();
			for(int i=0;i<issueListFull.length;i++) {
				URL issueUrl = issueListFull[i].getUrl();
				if(inscopeOnly && !callbacks.isInScope(issueUrl)) continue; //if only reporting in-scope issues and URL is not in-scope: discard issue and continue
				
				String reqProt = issueUrl.getProtocol();
				String reqHost = issueUrl.getHost();
				int reqPort = issueUrl.getPort();
				ArrayList<String> ppList = null;
				if(!siteKeys.contains(reqHost)) {
					ppList = new ArrayList<String>();
					ppList.add(reqProt+":"+Integer.toString(reqPort));
					sitesDict.put(reqHost,ppList);
					siteKeys = sitesDict.keySet();
				} else {
					ppList = (ArrayList<String>) sitesDict.get(reqHost);
					boolean found = false;
					Iterator<String> ppListItr = ppList.iterator();
					while(ppListItr.hasNext()) {
						if(ppListItr.next().equals(reqProt+":"+Integer.toString(reqPort))) {
							found = true;
							break;
						}
					}
					if(!found) {
						ppList.add(reqProt+":"+Integer.toString(reqPort));
						sitesDict.put(reqHost,ppList);
					}
				}
			}
			
			//issues met criteria for reporting: generate reports
			if(!siteKeys.isEmpty()) {
				if(!destDir.exists()) { //if chosen output folder does not exist, create it
					if(!destDir.mkdirs()) {
						callbacks.printOutput("Target directory"+destDir.getAbsolutePath()+" could not be created! Report generation aborted!\n");
						callbacks.printError("Target directory"+destDir.getAbsolutePath()+" could not be created! Report generation aborted!");
						statusLabel.setText("Target directory"+destDir.getAbsolutePath()+" directory could not be created! Report generation aborted!");
						reEnableUiElements();
						return;
					}
				} else if(!destDir.isDirectory()) { //if chosen output folder is not a directory
					callbacks.printOutput("Target "+destDir.getAbsolutePath()+" is not a directory! Report generation aborted!\n");
					callbacks.printError("Target "+destDir.getAbsolutePath()+" is not a directory! Report generation aborted!");
					statusLabel.setText("Target "+destDir.getAbsolutePath()+" is not a directory! Report generation aborted!");
					reEnableUiElements();
					return;
				}
				
				Hashtable<String,ArrayList<String>> reportList = new Hashtable<String,ArrayList<String>>();
				Iterator<String> siteKeysItr = siteKeys.iterator();
				while(siteKeysItr.hasNext()) {
					String site = siteKeysItr.next();
					ArrayList<String> ppList = sitesDict.get(site);
					
					if(mergeAll) {
						ArrayList<String> prefixList = new ArrayList<String>();
						Iterator<String> ppListItr = ppList.iterator();
						while(ppListItr.hasNext()) {
							String pp = ppListItr.next();
							String[] ppSplit = pp.split(":");
							if((ppSplit[0].equalsIgnoreCase("http")) && (ppSplit[1].equals("80"))) {
								prefixList.add("http://"+site+"/");
							} else if((ppSplit[0].equalsIgnoreCase("https")) && (ppSplit[1].equals("443"))) {
								prefixList.add("https://"+site+"/");
							} else {
								prefixList.add(ppSplit[0]+"://"+site+":"+ppSplit[1]+"/");
							}
						}
						if(prefixList.size()>0) {
							reportList.put(site+"_all",prefixList);
						}
					} else {
						if(mergeHttps) {
							ArrayList<String> stdPrefixList = new ArrayList<String>();
							boolean nonStdPort = false;
							Iterator<String> ppListItr = ppList.iterator();
							while(ppListItr.hasNext()) {
								String pp = ppListItr.next();
								String[] ppSplit = pp.split(":");
								if((ppSplit[0].equalsIgnoreCase("http")) && (ppSplit[1].equals("80"))) {
									stdPrefixList.add("http://"+site+"/");
								} else if((ppSplit[0].equalsIgnoreCase("https")) && (ppSplit[1].equals("443"))) {
									stdPrefixList.add("https://"+site+"/");
								} else {
									ArrayList<String> nonStdPrefixList = new ArrayList<String>(1);
									nonStdPrefixList.add(ppSplit[0]+"://"+site+":"+ppSplit[1]+"/");
									reportList.put(ppSplit[0]+"__"+site+"_"+ppSplit[1],nonStdPrefixList);
									nonStdPort = true;
								}
							}
							if(stdPrefixList.size()>0) {
								if(!nonStdPort) {
									reportList.put(site,stdPrefixList);
								} else {
									reportList.put("httphttps__"+site,stdPrefixList);
								}
							}
						} else {
							Iterator<String> ppListItr = ppList.iterator();
							while(ppListItr.hasNext()) {
								String pp = ppListItr.next();
								String[] ppSplit = pp.split(":");
								ArrayList<String> prefixList = new ArrayList<String>(1);
 								if((ppSplit[0].equalsIgnoreCase("http")) && (ppSplit[1].equals("80"))) {
									prefixList.add("http://"+site+"/");
									reportList.put(ppSplit[0]+"__"+site,prefixList);
								} else if((ppSplit[0].equalsIgnoreCase("https")) && (ppSplit[1].equals("443"))) {
									prefixList.add("https://"+site+"/");
									reportList.put(ppSplit[0]+"__"+site,prefixList);
								} else {
									prefixList.add(ppSplit[0]+"://"+site+":"+ppSplit[1]+"/");
									reportList.put(ppSplit[0]+"__"+site+"_"+ppSplit[1],prefixList);
								}
							}
						}
					}
				}
				
				//Determine if issues should be filtered by severity and/or confidence
				boolean sevFilter = false;
				boolean conFilter = false;
				for(int k=0;k<severities.length;k++) {
					if(severities[k]!=true) {
						sevFilter = true;
						break;
					}
				}
				for(int k=0;k<confidences.length;k++) {
					if(confidences[k]!=true) {
						conFilter = true;
						break;
					}
				}
				
				Set<String> reportSites = reportList.keySet();
				Hashtable<String,IScanIssue[]> reportIssues = new Hashtable<String,IScanIssue[]>();
				Iterator<String> reportIssuesItr = reportSites.iterator();
				while(reportIssuesItr.hasNext()) {
					String site = reportIssuesItr.next();
					ArrayList<IScanIssue> issueList = new ArrayList<IScanIssue>();
					ArrayList<String> prefixList = reportList.get(site);
					Iterator<String> prefixListItr = prefixList.iterator();
					while(prefixListItr.hasNext()) {
						IScanIssue[] issueTempList = callbacks.getScanIssues(prefixListItr.next());
						for(int k=0;k<issueTempList.length;k++) {
							//filter issues by severity and/or confidence (if applicable)
							if(sevFilter) {
								String severity = issueTempList[k].getSeverity();
								if(severity.equalsIgnoreCase("High")) {
									if(severities[0]!=true) continue;
								} else if(severity.equalsIgnoreCase("Medium")) {
									if(severities[1]!=true) continue;
								} else if(severity.equalsIgnoreCase("Low")) {
									if(severities[2]!=true) continue;
								} else if(severity.equalsIgnoreCase("Information")) {
									if(severities[3]!=true) continue;
								} else if(severity.equalsIgnoreCase("False Positive")) {
									if(severities[4]!=true) continue;
								}
							}
							if(conFilter) {
								String confidence = issueTempList[k].getConfidence();
								if(confidence.equalsIgnoreCase("Certain")) {
									if(confidences[0]!=true) continue;
								} else if(confidence.equalsIgnoreCase("Firm")) {
									if(confidences[1]!=true) continue;
								} else if(confidence.equalsIgnoreCase("Tentative")) {
									if(confidences[2]!=true) continue;
								}
							}
							issueList.add(issueTempList[k]);
						}
					}
					if(issueList.size()>0) {
						IScanIssue[] tempArr = new IScanIssue[issueList.size()];
						IScanIssue[] issueArr = issueList.toArray(tempArr);
						reportIssues.put(site+"-burp."+reportFormat.toLowerCase(),issueArr);
					}
				}
				
				Set<String> reportFilenames = reportIssues.keySet();
				if(reportFilenames.size()==0) {
					callbacks.printOutput("No reports generated: Sites matching requirements contained no issues to report!\n");
					callbacks.printError("No reports generated: Sites matching requirements contained no issues to report!");
					statusLabel.setText("No reports generated: Sites matching requirements contained no issues to report!");
					reEnableUiElements();
					return;
				}
				callbacks.printOutput("Starting report generation of "+Integer.toString(reportFilenames.size())+" reports");
				statusLabel.setText("Starting report generation of "+Integer.toString(reportFilenames.size())+" reports...");
				Iterator<String> reportFilenamesItr = reportFilenames.iterator();
				int count = 1;
				while(reportFilenamesItr.hasNext()) {
					String filename = reportFilenamesItr.next();
					callbacks.printOutput("Generating report "+Integer.toString(count)+" of "+Integer.toString(reportFilenames.size()));
					statusLabel.setText("Generating report "+Integer.toString(count)+" of "+Integer.toString(reportFilenames.size())+"...");
					IScanIssue[] issueList = reportIssues.get(filename);
					if(fileDate) {
						filename = filename.substring(0,filename.length()-(reportFormat.toLowerCase().length()+1))+"-";
						SimpleDateFormat sdf = new SimpleDateFormat(dateFormats[dateFormatChooser.getSelectedIndex()]);
						filename += sdf.format(new Date())+"."+reportFormat.toLowerCase();
					}
					File reportFile = null;
					if(createSubDirectories) {
						File subDirFile = new File(destDir,issueList[0].getHttpService().getHost());
						if(!subDirFile.exists()) { //if chosen output folder does not exist, create it
							if(!subDirFile.mkdirs()) {
								callbacks.printOutput("Host sub-directory "+subDirFile.getAbsolutePath()+" could not be created! Report generation aborted!\n");
								callbacks.printError("Host sub-directory "+subDirFile.getAbsolutePath()+" could not be created! Report generation aborted!");
								statusLabel.setText(subDirFile.getAbsolutePath()+" directory could not be created! Report generation aborted!");
								reEnableUiElements();
								return;
							}
						} else if(!destDir.isDirectory()) { //if chosen output folder is not a directory
							callbacks.printOutput(destDir.getAbsolutePath()+" is not a directory! Report generation aborted!\n");
							callbacks.printError(destDir.getAbsolutePath()+" is not a directory! Report generation aborted!");
							statusLabel.setText(destDir.getAbsolutePath()+" is not a directory! Report generation aborted!");
							reEnableUiElements();
							return;
						}
						reportFile = new File(subDirFile,filename);
					} else {
						reportFile = new File(destDir,filename);
					}
					callbacks.generateScanReport(reportFormat.toUpperCase(),issueList,reportFile);
					callbacks.printOutput("Report "+Integer.toString(count)+" ("+reportFile.getAbsolutePath()+") of "+Integer.toString(reportFilenames.size())+" generated successfully!");
					statusLabel.setText("Generating report "+Integer.toString(count)+" of "+Integer.toString(reportFilenames.size())+"...");
					count++;
				}
				callbacks.printOutput("Report Generation Complete!\n");
				statusLabel.setText("Report Generation Complete!");
				
			} else {
				callbacks.printOutput("No reports generated: No sites match requirements for report generation!\n");
				callbacks.printError("No reports generated: No sites match requirements for report generation!");
				statusLabel.setText("No reports generated: No sites match requirements for report generation!");
			}
			
			reEnableUiElements();
			return;
		}
		
		private void reEnableUiElements() {
			generateButton.setEnabled(true);
			generateButton.setText("Generate Report(s)");
			htmlButton.setEnabled(true);
			xmlButton.setEnabled(true);
			includeHighSeverityCheck.setEnabled(true);
			includeMediumSeverityCheck.setEnabled(true);
			includeLowSeverityCheck.setEnabled(true);
			includeInformationSeverityCheck.setEnabled(true);
			includeFalsePositiveSeverityCheck.setEnabled(true);
			includeCertainConfidenceCheck.setEnabled(true);
			includeFirmConfidenceCheck.setEnabled(true);
			includeTentativeConfidenceCheck.setEnabled(true);
			inscopeCheck.setEnabled(true);
			httpsCheck.setEnabled(!mergeAll);
			mergeAllCheck.setEnabled(true);
			destDirButton.setEnabled(true);
			filenameDateCheck.setEnabled(true);
			dateFormatChooser.setEnabled(fileDate);
			createSubDirectoriesCheck.setEnabled(true);
			return;
		}
	}
}
