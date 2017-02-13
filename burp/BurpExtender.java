/*
	BurpExtender.java
	
	v0.1 (2/7/2017)
	
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
import javax.swing.JFileChooser;
import javax.swing.JButton;
import javax.swing.SwingConstants;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.FlowLayout;
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
	private boolean inscopeOnly;
	private boolean mergeHttps; //merge http:80 and https:443 into one report
	private boolean mergeAll; //merge all protocols and ports into 1 report
	private File destDir;
	private boolean fileDate; //append generation date to filename in format MMDDYYYY
	
	//UI fields
	private JPanel component;
	private JRadioButton htmlButton;
	private JRadioButton xmlButton;
	private JCheckBox inscopeCheck;
	private JCheckBox httpsCheck;
	private JCheckBox mergeAllCheck;
	private JFileChooser destDirChooser;
	private JButton destDirButton;
	private JLabel destDirLabel;
	private JCheckBox filenameDateCheck;
	private JButton generateButton;
	private JLabel statusLabel;
	
	//constants
	private static final String VERSION = "0.1";
	
	//IBurpExtender methods
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks cb) {
		callbacks = cb;
		helpers = callbacks.getHelpers();
		name = "Batch Scan Report Generator";
		callbacks.setExtensionName(name+" v"+VERSION);
		
		//initialized default settings
		reportFormat = "HTML";
		inscopeOnly = true;
		mergeHttps = true;
		mergeAll = false;
		destDir = new File(System.getProperty("java.io.tmpdir"));
		fileDate = false;
		
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
		
		JPanel innerPanel = new JPanel(new GridLayout(7,2,2,0));
		innerPanel.add(new JLabel("Report Output Format:",SwingConstants.RIGHT));
		htmlButton = new JRadioButton("HTML",true); //ActionListener needed
		htmlButton.addActionListener(this);
		htmlButton.setActionCommand("HTML");
		xmlButton = new JRadioButton("XML",false); //ActionListener needed
		xmlButton.addActionListener(this);
		xmlButton.setActionCommand("XML");
		ButtonGroup bg = new ButtonGroup();
		bg.add(htmlButton);
		bg.add(xmlButton);
		JPanel buttonPanel = new JPanel(new GridLayout(2,1));
		buttonPanel.add(htmlButton);
		buttonPanel.add(xmlButton);
		innerPanel.add(buttonPanel);
		innerPanel.add(new JLabel("Report On In-Scope Sites Only:",SwingConstants.RIGHT));
		inscopeCheck = new JCheckBox((String) null,true); //ActionListener needed
		inscopeCheck.addActionListener(this);
		innerPanel.add(inscopeCheck);
		innerPanel.add(new JLabel("Merge HTTP (port 80) and HTTPS (port 443) For Reports:",SwingConstants.RIGHT));
		httpsCheck = new JCheckBox((String) null,true); //ActionListener needed
		httpsCheck.addActionListener(this);
		innerPanel.add(httpsCheck);
		innerPanel.add(new JLabel("One Host Per Report (Combine All Protocols and Ports):",SwingConstants.RIGHT));
		mergeAllCheck = new JCheckBox((String) null,false); //ActionListener needed
		mergeAllCheck.addActionListener(this);
		innerPanel.add(mergeAllCheck);
		innerPanel.add(new JLabel("Report Output Root Directory:",SwingConstants.RIGHT));
		destDirChooser = new JFileChooser();
		destDirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		JPanel dirPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		destDirButton = new JButton("Select folder ..."); //ActionListener needed
		destDirButton.addActionListener(this);
		destDirLabel = new JLabel(destDir.getAbsolutePath());
		dirPanel.add(destDirButton);
		dirPanel.add(destDirLabel);
		innerPanel.add(dirPanel);
		innerPanel.add(new JLabel("Append Date To Report Filenames:",SwingConstants.RIGHT));
		filenameDateCheck = new JCheckBox((String) null,false); //ActionListener needed
		filenameDateCheck.addActionListener(this);
		innerPanel.add(filenameDateCheck);
		generateButton = new JButton("Generate Report(s)"); //ActionListener needed
		generateButton.addActionListener(this);
		innerPanel.add(generateButton);
		statusLabel = new JLabel();
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
		} else if(source == generateButton) {
			Thread genThread = new Thread(new GenerateThread());
			genThread.start();
		}
	}
	
	
	//private "Report Generation Thread" class
	private class GenerateThread implements Runnable {
		public void run() {
			generateButton.setText("Generating Report(s), Please Wait...");
			generateButton.setEnabled(false);
			htmlButton.setEnabled(false);
			xmlButton.setEnabled(false);
			inscopeCheck.setEnabled(false);
			httpsCheck.setEnabled(false);
			boolean mergeAllSet = mergeAllCheck.isEnabled();
			mergeAllCheck.setEnabled(false);
			destDirButton.setEnabled(false);
			filenameDateCheck.setEnabled(false);
			callbacks.printOutput("Reading Full List of Issues");
			statusLabel.setText("<html><font color=\'orange\'>Reading Full List of Issues...</font></html>");
			
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
						callbacks.printError(destDir.getAbsolutePath()+" could not be created!");
						statusLabel.setText("<html><font color=\'orange\'>"+destDir.getAbsolutePath()+" directory could not be created!</font></html>");
						
						generateButton.setEnabled(true);
						generateButton.setText("Generate Report(s)");
						htmlButton.setEnabled(true);
						xmlButton.setEnabled(true);
						inscopeCheck.setEnabled(true);
						if(!mergeAllSet) httpsCheck.setEnabled(true);
						mergeAllCheck.setEnabled(true);
						destDirButton.setEnabled(true);
						filenameDateCheck.setEnabled(true);
						return;
					}
				} else if(!destDir.isDirectory()) { //if chosen output folder is not a directory
					callbacks.printError(destDir.getAbsolutePath()+" is not a directory!");
					statusLabel.setText("<html><font color=\'orange\'>"+destDir.getAbsolutePath()+" is not a directory!</font></html>");
					
					generateButton.setEnabled(true);
					generateButton.setText("Generate Report(s)");
					htmlButton.setEnabled(true);
					xmlButton.setEnabled(true);
					inscopeCheck.setEnabled(true);
					if(!mergeAllSet) httpsCheck.setEnabled(true);
					mergeAllCheck.setEnabled(true);
					destDirButton.setEnabled(true);
					filenameDateCheck.setEnabled(true);
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
				callbacks.printOutput("Starting report generation of "+Integer.toString(reportFilenames.size())+" reports");
				statusLabel.setText("<html><font color=\'orange\'>Starting report generation of "+Integer.toString(reportFilenames.size())+" reports...</font></html>");
				Iterator<String> reportFilenamesItr = reportFilenames.iterator();
				int count = 1;
				while(reportFilenamesItr.hasNext()) {
					String filename = reportFilenamesItr.next();
					statusLabel.setText("<html><font color=\'orange\'>Generating report "+Integer.toString(count)+" of "+Integer.toString(reportFilenames.size())+"...</font></html>");
					IScanIssue[] issueList = reportIssues.get(filename);
					if(fileDate) {
						filename = filename.substring(0,filename.length()-(reportFormat.toLowerCase().length()+1))+"-";
						Date today = new Date();
						SimpleDateFormat sdf = new SimpleDateFormat("MMDDYYYY");
						filename += sdf.format(today)+"."+reportFormat.toLowerCase();
					}
					File reportFile = new File(destDir,filename);
					callbacks.generateScanReport(reportFormat.toUpperCase(),issueList,reportFile);
					callbacks.printOutput("Report "+Integer.toString(count)+" ("+reportFile.getAbsolutePath()+") of "+Integer.toString(reportFilenames.size())+" generated successfully!");
					count++;
				}
				callbacks.printOutput("Report Generation Complete!");
				statusLabel.setText("<html><font color=\'orange\'>Report Generation Complete!</font></html>");
				
			} else {
				callbacks.printError("No reports generated: No sites match requirements for report generation!");
				statusLabel.setText("<html><font color=\'orange\'>No reports generated: No sites match requirements for report generation!</font></html>");
			}
			
			generateButton.setEnabled(true);
			generateButton.setText("Generate Report(s)");
			htmlButton.setEnabled(true);
			xmlButton.setEnabled(true);
			inscopeCheck.setEnabled(true);
			if(!mergeAllSet) httpsCheck.setEnabled(true);
			mergeAllCheck.setEnabled(true);
			destDirButton.setEnabled(true);
			filenameDateCheck.setEnabled(true);
		}
	}
}
