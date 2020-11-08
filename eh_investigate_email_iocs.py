"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_community_list_drop_none_1' block
    cf_community_list_drop_none_1(container=container)

    # call 'cf_local_assign_workbook_by_name_1' block
    cf_local_assign_workbook_by_name_1(container=container)

    # call 'cf_community_list_drop_none_2' block
    cf_community_list_drop_none_2(container=container)

    # call 'cf_community_list_drop_none_3' block
    cf_community_list_drop_none_3(container=container)

    # call 'cf_community_list_drop_none_4' block
    cf_community_list_drop_none_4(container=container)

    return

def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'url_reputation_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_community_list_drop_none_2:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'url_reputation_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'url': custom_function_results_item_1[0],
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal'], callback=decision_4, name="url_reputation_1")

    return

def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_community_list_drop_none_1:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'ip': custom_function_results_item_1[0],
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal'], callback=decision_3, name="ip_reputation_1")

    return

def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'domain_reputation_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_community_list_drop_none_3:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'domain': custom_function_results_item_1[0],
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['virustotal'], callback=decision_2, name="domain_reputation_1")

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'file_reputation_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_community_list_drop_none_4:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'hash': custom_function_results_item_1[0],
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=decision_1, name="file_reputation_1")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", ">=", 3],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    format_11(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_1:action_result.summary.positives", ">=", 3],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    format_10(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_1:action_result.summary.positives", ">=", 3],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    format_9(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:action_result.summary.positives", ">=", 3],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        format_7(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    format_8(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def add_note_add_comment_set_severity_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_add_comment_set_severity_5() called')

    formatted_data_1 = phantom.get_format_data(name='format_3')

    note_title = "Malicious URL Found in Email Content"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.comment(container=container, comment=formatted_data_1)

    phantom.set_severity(container=container, severity="High")
    join_playbook_local_local_eh_promote_to_case_1(container=container)

    return

def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_3() called')
    
    template = """VirusTotal has determined that the email contains {0} positive results against the URL {1}. As there have been a large number of positive detections, this phishing attempt is being made into an incident. Further investigation and remediation activities should be taken."""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation_1:action_result.summary.positives",
        "url_reputation_1:action_result.parameter.url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    add_note_add_comment_set_severity_5(container=container)

    return

def format_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_4() called')
    
    template = """VirusTotal has determined that the email contains {0} positive results against the IP Address {1}. As there have been a large number of positive detections, this phishing attempt is being made into an incident and remediation actions are being taken.
{1}"""

    # parameter list for template variable replacement
    parameters = [
        "ip_reputation_1:action_result.summary.positives",
        "ip_reputation_1:action_result.parameter.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_4")

    add_comment_add_note_pin_promote_to_case_set_severity_9(container=container)

    return

def format_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_5() called')
    
    template = """VirusTotal has determined that the email contains {0} positive results against the domain {1}. As there have been a large number of positive detections, this phishing attempt is being made into an incident and remediation actions are being taken."""

    # parameter list for template variable replacement
    parameters = [
        "domain_reputation_1:action_result.summary.positives",
        "domain_reputation_1:action_result.parameter.domain",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_5")

    add_comment_add_note_pin_set_severity_promote_to_case_10(container=container)

    return

def format_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_6() called')
    
    template = """VirusTotal has determined that the email contains {0} positive results against the file {1}. As there have been a large number of positive detections, this phishing attempt is being made into an incident and remediation actions are being taken."""

    # parameter list for template variable replacement
    parameters = [
        "file_reputation_1:action_result.summary.positives",
        "file_reputation_1:action_result.parameter.hash",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_6")

    add_comment_add_note_pin_set_severity_promote_to_case_11(container=container)

    return

def add_comment_add_note_pin_promote_to_case_set_severity_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_add_note_pin_promote_to_case_set_severity_9() called')

    formatted_data_1 = phantom.get_format_data(name='format_4')

    phantom.comment(container=container, comment=formatted_data_1)

    note_title = "Phishing Email Detected"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.pin(container=container, data=formatted_data_1, message="Phishing Email Detected", pin_type="card", pin_style="red", name=None)

    phantom.promote(container=container, template="NIST 800-61")

    phantom.set_severity(container=container, severity="High")
    join_playbook_local_local_eh_promote_to_case_1(container=container)

    return

def add_comment_add_note_pin_set_severity_promote_to_case_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_add_note_pin_set_severity_promote_to_case_10() called')

    formatted_data_1 = phantom.get_format_data(name='format_5')

    phantom.comment(container=container, comment=formatted_data_1)

    note_title = "Phishing Email Detected"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.pin(container=container, data=formatted_data_1, message="Phishing Email Detected", pin_type="card", pin_style="red", name=None)

    phantom.set_severity(container=container, severity="High")

    phantom.promote(container=container, template="NIST 800-61")
    join_playbook_local_local_eh_promote_to_case_1(container=container)

    return

def add_comment_add_note_pin_set_severity_promote_to_case_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_add_note_pin_set_severity_promote_to_case_11() called')

    formatted_data_1 = phantom.get_format_data(name='format_6')

    phantom.comment(container=container, comment=formatted_data_1)

    note_title = "Phishing Email Detected"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.pin(container=container, data=formatted_data_1, message="Phishing Email Detected", pin_type="card", pin_style="red", name=None)

    phantom.set_severity(container=container, severity="High")

    phantom.promote(container=container, template="NIST 800-61")
    join_playbook_local_local_eh_promote_to_case_1(container=container)

    return

def format_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_7() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation_1:action_result.parameter.url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_7")

    pin_13(container=container)

    return

def playbook_local_local_eh_promote_to_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_local_eh_promote_to_case_1() called')
    
    # call playbook "local/eh_promote_to_case", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/eh_promote_to_case", container=container)
    cf_community_list_drop_none_5(container=container)

    return

def join_playbook_local_local_eh_promote_to_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_playbook_local_local_eh_promote_to_case_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_playbook_local_local_eh_promote_to_case_1_called'):
        return

    # no callbacks to check, call connected block "playbook_local_local_eh_promote_to_case_1"
    phantom.save_run_data(key='join_playbook_local_local_eh_promote_to_case_1_called', value='playbook_local_local_eh_promote_to_case_1', auto=True)

    playbook_local_local_eh_promote_to_case_1(container=container, handle=handle)
    
    return

def pin_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_13() called')

    formatted_data_1 = phantom.get_format_data(name='format_7')

    phantom.pin(container=container, data=formatted_data_1, message="Phishing Email Detected", pin_type="card", pin_style="red", name=None)

    return

def format_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_8() called')
    
    template = """The URL \"{0}\" was not found to be malicious."""

    # parameter list for template variable replacement
    parameters = [
        "cf_community_list_drop_none_2:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_8")

    add_comment_add_note_14(container=container)

    return

def add_comment_add_note_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_add_note_14() called')

    formatted_data_1 = phantom.get_format_data(name='format_8')

    phantom.comment(container=container, comment=formatted_data_1)

    note_title = "No Malicious URLs"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def whois_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_ip_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_ip_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_community_list_drop_none_1:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_ip_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'ip': custom_function_results_item_1[0],
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], name="whois_ip_1")

    return

def format_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_9() called')
    
    template = """The IP address \"{0}\" was not found to be malicious."""

    # parameter list for template variable replacement
    parameters = [
        "cf_community_list_drop_none_1:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_9")

    add_comment_add_note_15(container=container)

    return

def add_comment_add_note_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_add_note_15() called')

    formatted_data_1 = phantom.get_format_data(name='format_9')

    phantom.comment(container=container, comment=formatted_data_1)

    note_title = "No Malicious IP Addresses"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def whois_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_domain_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_domain_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_community_list_drop_none_3:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_domain_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'domain': custom_function_results_item_1[0],
            })

    phantom.act(action="whois domain", parameters=parameters, assets=['whois'], name="whois_domain_1")

    return

def format_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_10() called')
    
    template = """The Domains \"{0}\" were not found to be malicious."""

    # parameter list for template variable replacement
    parameters = [
        "cf_community_list_drop_none_3:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_10")

    add_note_add_comment_16(container=container)

    return

def format_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_11() called')
    
    template = """The file hashes \"{0}\" were not found to be malicious"""

    # parameter list for template variable replacement
    parameters = [
        "cf_community_list_drop_none_4:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_11")

    add_note_add_comment_17(container=container)

    return

def add_note_add_comment_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_add_comment_16() called')

    formatted_data_1 = phantom.get_format_data(name='format_10')

    note_title = "No Malicious Domains"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.comment(container=container, comment=formatted_data_1)

    return

def add_note_add_comment_17(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_add_comment_17() called')

    formatted_data_1 = phantom.get_format_data(name='format_11')

    note_title = "No Malicious File Hashes"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.comment(container=container, comment=formatted_data_1)

    return

def add_comment_add_note_18(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_add_note_18() called')

    phantom.comment(container=container, comment="No URLs found within email.")

    note_title = "No URLs Present in Email"
    note_content = "No URLs were extracted out of the email contents."
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def add_comment_add_note_19(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_add_note_19() called')

    phantom.comment(container=container, comment="No domain information found within the email")

    note_title = "No Domains Present in Email"
    note_content = "No domain information was extracted from the email contents"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def add_comment_add_note_20(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_add_note_20() called')

    phantom.comment(container=container, comment="No IP address information found in email")

    note_title = "No IP Addresses Present in Email"
    note_content = "No IP address information was extracted from the email contents"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def add_comment_add_note_21(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_add_note_21() called')

    phantom.comment(container=container, comment="No file hash information found within email")

    note_title = "No File Hash Information Present in Email"
    note_content = "No file hash information was extracted from the contents of the email"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def cf_community_list_drop_none_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_list_drop_none_1() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.emailHeaders.X-MDRemoteIP', 'artifact:*.id'])

    parameters = []

    container_data_0_0 = [item[0] for item in container_data_0]

    parameters.append({
        'input_list': container_data_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/list_drop_none", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/list_drop_none', parameters=parameters, name='cf_community_list_drop_none_1', callback=decision_6)

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_community_list_drop_none_2:custom_function_result.data.*.item", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        url_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_comment_add_note_18(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_community_list_drop_none_1:custom_function_result.data.*.item", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        whois_ip_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_comment_add_note_20(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def cf_local_assign_workbook_by_name_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_assign_workbook_by_name_1() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "m_phishingInvestigation",
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        for item1 in literal_values_0:
            parameters.append({
                'container_id': item0[0],
                'workbook_name': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/assign_workbook_by_name", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/assign_workbook_by_name', parameters=parameters, name='cf_local_assign_workbook_by_name_1')

    return

def cf_community_list_drop_none_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_list_drop_none_2() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []

    container_data_0_0 = [item[0] for item in container_data_0]

    parameters.append({
        'input_list': container_data_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/list_drop_none", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/list_drop_none', parameters=parameters, name='cf_community_list_drop_none_2', callback=decision_5)

    return

def cf_community_list_drop_none_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_list_drop_none_3() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []

    container_data_0_0 = [item[0] for item in container_data_0]

    parameters.append({
        'input_list': container_data_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/list_drop_none", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/list_drop_none', parameters=parameters, name='cf_community_list_drop_none_3', callback=decision_7)

    return

def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_7() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_community_list_drop_none_3:custom_function_result.data.*.item", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        domain_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        whois_domain_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_comment_add_note_19(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def cf_community_list_drop_none_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_list_drop_none_4() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHashSha1', 'artifact:*.id'])

    parameters = []

    container_data_0_0 = [item[0] for item in container_data_0]

    parameters.append({
        'input_list': container_data_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/list_drop_none", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/list_drop_none', parameters=parameters, name='cf_community_list_drop_none_4', callback=decision_8)

    return

def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_8() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_community_list_drop_none_4:custom_function_result.data.*.item", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        file_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_comment_add_note_21(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def pin_23(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_23() called')

    formatted_data_1 = phantom.get_format_data(name='format_12')

    phantom.pin(container=container, data=formatted_data_1, message="Malicious Email Subject:", pin_type="card", pin_style="red", name=None)

    return

def cf_community_list_drop_none_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_list_drop_none_5() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.emailHeaders.Subject', 'artifact:*.id'])

    parameters = []

    container_data_0_0 = [item[0] for item in container_data_0]

    parameters.append({
        'input_list': container_data_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/list_drop_none", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/list_drop_none', parameters=parameters, name='cf_community_list_drop_none_5', callback=format_12)

    return

def format_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_12() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "cf_community_list_drop_none_5:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_12")

    pin_23(container=container)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return