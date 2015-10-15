#!/usr/bin/env python
#
# this script will report in a  jira ticket
# the result of a nessus scan
# exemple : nessus scan scan_WEBSITE will report in jira WEBSITE project
# One ticket by hosts
#

import sys
sys.path.append('../')
from nessrest import ness6rest
from jira import JIRA

# Nessus credentials and setup
my_api_akey = ''
my_api_skey = ''
scan = ness6rest.Scanner(url="https://nessusscanner:8834",api_akey=my_api_akey,api_skey=my_api_skey, insecure=True)

# Jira Credential and setup
options = {
    'server': 'https://jira.atlassian.com
}
jira = JIRA(options,basic_auth=('', ''))
# or using OAuth
# key_cert_data = None
# with open(key_cert, 'r') as key_cert_file:
#     key_cert_data = key_cert_file.read()
#
# oauth_dict = {
#     'access_token': 'd87f3hajglkjh89a97f8',
#     'access_token_secret': 'a9f8ag0ehaljkhgeds90',
#     'consumer_key': 'jira-oauth-consumer',
#     'key_cert': key_cert_data
# }
# authed_jira = JIRA(oauth=oauth_dict)

#parsing all the project to search for corresponding scan in nessus
projects = jira.projects()
for project in projects:
    if not scan.scan_exists(name="scan_"+project.key):
        print "No Nessus scan exist for project "+project.key
    else:
        print "Nessus scan exist for project "+project.key+": starting it"
        scan._scan_tag(name="My Scans")
        #you need to create a policy in nessus
        scan.policy_set("nessus2jira")

        #running tests
        scan.scan_run()
        scan._scan_status()

        #fetch result
        scan.get_host_vulns(name="scan_"+project.key)
        for scan_id in scan.host_vulns:
            print scan_id
            for host_id in scan.host_vulns[scan_id]:
                num_vuln = 0
                description="list of pending vulnerabilities:\n"
                for vulns in scan.host_vulns[scan_id][host_id]["vulnerabilities"]:
                    #if the server cant be ping , raise a warning
                    if (vulns["plugin_id"] == 10180):
                        num_vuln = num_vuln + 1
                        summary = ("[SCAN] The remote host %s is considered as dead - not scanning\n" %
                        (scan.host_vulns[scan_id][host_id]["info"]["host-ip"]))
                    if (vulns["severity"] > 2):
                        num_vuln = num_vuln + 1
                        description = description + "%s, severity: %s\n" % (vulns["plugin_name"],vulns["severity"])
                        summary = ("[SCAN] %s: %i patch(s) pending" %
                        (scan.host_vulns[scan_id][host_id]["info"]["host-ip"],num_vuln))

                # Opening a new jira ticket or updating existing one
                already_open = jira.search_issues('project = \'' + project.key + '\' '
                                'AND summary ~ \'SCAN\' ' +
                                'AND summary ~ ' +
                                scan.host_vulns[scan_id][host_id]["info"]["host-ip"])
                if already_open:
                    print("%s: UPDATING jira ticket: %s" %
                        (scan.host_vulns[scan_id][host_id]["info"]["host-ip"],already_open[0]))
                    issue = jira.issue(already_open[0])
                    if num_vuln:
                        print "still have some vuln: ensure it is open or reopen by forcing reopen status"
                        if jira.find_transitionid_by_name(issue, "reopen issue"):
                            print("status change from %s to reopen issue" % issue.fields.status)
                            jira.transition_issue(issue, jira.find_transitionid_by_name(issue, "reopen issue"))
                        issue.update(summary=summary, description=description)
                    else:
                        print "no more vuln: closing"
                        if jira.find_transitionid_by_name(issue, "resolved issue"):
                            print("status change from %s to resolved issue" % issue.fields.status)
                            jira.transition_issue(issue, jira.find_transitionid_by_name(issue, "resolved issue"))
                        issue.update(summary='[SCAN] %s: no patch pending' %
                                scan.host_vulns[scan_id][host_id]["info"]["host-ip"],
                                description="No vulnerabilities , Good Job !")
                elif num_vuln:
                    print("%s: CREATING NEW jira ticket" %
                        (scan.host_vulns[scan_id][host_id]["info"]["host-ip"]))
                    print jira.create_issue(project=project.key, summary=summary,
                        description=description, issuetype={'name': 'Improvement'})
                else:
                    print("%s: no vulnerabilities, no jira ticket !" %
                        (scan.host_vulns[scan_id][host_id]["info"]["host-ip"]))
