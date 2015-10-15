This python script allow you to import [Tenable Nessus scan](http://http://www.tenable.com/products/nessus-vulnerability-scanner) result to [Atlassian Jira](https://www.atlassian.com/software/jira) task tracking system.

### Dependencies

* Nessus server scanner 6.4.x
* JIRA server
* Python 2.7+ or 3.3+
* [Python JIRA Library](http://pythonhosted.org/jira/)
* [ness6rest.py](https://github.com/tenable/nessrest)



### Usage

this script will report in  jira tickets the result of a nessus scan

exemple : nessus scan "scan_WEBSITE" will report in jira "WEBSITE" project, one ticket per hosts

### configuration

* You need to setup a scan in nessus matching one of you jira project
* You need provide valid credential (or API key) to acces both Nessus and Jira API
