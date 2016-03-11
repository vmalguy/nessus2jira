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
import ConfigParser

# source configuration
config = ConfigParser.ConfigParser()
config.readfp(open('./nessus2jira.cfg'))

# Nessus credentials and setup
scan_policy = "nessus2jira"
tag_name = config.get("nessus", "tag_name")
scan = ness6rest.Scanner(url=config.get("nessus", "url"),
                         api_akey=config.get("nessus", "api_akey"),
                         api_skey=config.get("nessus", "api_skey"),
                         insecure=config.get("nessus", "insecure"))
# scan policy must be created under "Advanced" sections

# Jira Credential and setup
options = {
    'server': config.get("jira", "server")
}
jira = JIRA(options, basic_auth=(config.get("jira", "user"),
                                 config.get("jira", "password")))


def build_issue(project_key, host_result):
    num_vuln = 0
    description = "list of pending vulnerabilities:\n"
    summary = ""
    for vuln in host_result["vulnerabilities"]:
        # If the server cant be ping , raise a warning
        if (vuln["plugin_id"] == 10180):
            num_vuln = num_vuln + 1
            summary = ("[SCAN] The remote host %s is considered as dead \
            - not scanning" % (host_result["info"]["host-ip"]))
        if (vuln["severity"] > 2):
            num_vuln = num_vuln + 1
            description = description + ("%s, severity: %s\n" %
                                         (vuln["plugin_name"],
                                          vuln["severity"]))
            summary = ("[SCAN] %s: %i patch(s) pending" %
                       (host_result["info"]["host-ip"], num_vuln))
    issue = {
        'project': project_key,
        'summary': summary,
        'description': description,
        'issuetype': {'name': 'Improvement'},
    }
    return (issue, num_vuln)


def find_issue(project_key, host_ip):
    return jira.search_issues('project = \'' + project_key
                              + '\' ' +
                              'AND summary ~ \'SCAN\' ' +
                              'AND summary ~ ' + host_ip)


def update_jira_ticket(host_result, ticket_id, num_vuln, issue_dict):
    if ticket_id:
        print("%s: UPDATING jira ticket: %s" %
              (host_result["info"]["host-ip"], ticket_id[0]))
        issue = jira.issue(ticket_id[0])
        if num_vuln:
            print "still have some vuln, ensure it is open or \
                    reopen by forcing reopen status"
            if jira.find_transitionid_by_name(issue,
                                              "reopen issue"):
                print("status change from %s to reopen issue" %
                      issue.fields.status)
                jira.transition_issue(issue,
                                      jira.find_transitionid_by_name
                                      (issue, "reopen issue"))
            # print issue_dict
            issue.update(summary=issue_dict['summary'],
                         description=issue_dict['description'])
        else:
            print "no more vuln: closing"
            trans_id = jira.find_transitionid_by_name(issue, "resolved issue")
            if trans_id:
                print("status change from %s to resolved issue" %
                      issue.fields.status)
                jira.transition_issue(issue, trans_id)
            issue.update(summary='[SCAN] %s: no patch pending' %
                         host_result
                         ["info"]["host-ip"],
                         description="No vulnerabilities, Good Job !")
    elif num_vuln:
        print("%s: CREATING NEW jira ticket" %
              (host_result
               ["info"]["host-ip"]))
        # issue_dict = dict(project=project.key,
        #                  issuetype={'name': 'Improvement'})
        print jira.create_issue(fields=issue_dict)
    else:
        print("%s: no vulnerabilities, no jira ticket !" %
              (host_result
               ["info"]["host-ip"]))


# Parsing all the project to search for corresponding scan in nessus
projects = jira.projects()
for project in projects:
    if not scan.scan_exists(name="scan_"+project.key):
        # print "No Nessus scan exist for project "+project.key
        pass
    else:
        print "Nessus scan exist for project "+project.key+": starting it"
        scan._scan_tag(name="My Scans")
        scan.policy_set(scan_policy)

        # Running tests
        scan.scan_run()
        scan._scan_status()

        # Parse scan result
        scan.get_host_vulns(name="scan_"+project.key)
        for scan_id in scan.host_vulns:
            print scan_id
            for host_id in scan.host_vulns[scan_id]:
                issue_dict, n_vuln = build_issue(project.key, scan.host_vulns
                                                 [scan_id][host_id])

                # Opening a new jira ticket or updating existing one
                update_jira_ticket(scan.host_vulns[scan_id][host_id],
                                   find_issue(project.key, scan.host_vulns
                                              [scan_id][host_id]
                                              ["info"]["host-ip"]),
                                   n_vuln, issue_dict)
