"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    return

def promote_to_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('promote_to_case_1() called')

    phantom.promote(container=container, template="NSW eHealth Incident Investigation")
    set_owner_3(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')
    
    label_param = container.get('label', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            [label_param, "==", "events"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        promote_to_case_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        cf_local_assign_workbook_by_name_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def New_Case_Assigned(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('New_Case_Assigned() called')
    
    # set user and message variables for phantom.prompt call
    user = "Incident Commander"
    message = """A new case has been assigned: {0}. Please acknowledge you have received this notification."""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="New_Case_Assigned", parameters=parameters, response_types=response_types, callback=format_2)

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """The case has been assigned to: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "container:owner",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    add_comment_4(container=container)

    return

def set_owner_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_owner_3() called')

    phantom.set_owner(container=container, user="admin")
    New_Case_Assigned(container=container)
    playbook_local_local_eh_phishing_generate_drilldowns_1(container=container)

    return

def add_comment_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_4() called')

    formatted_data_1 = phantom.get_format_data(name='format_2')

    phantom.comment(container=container, comment=formatted_data_1)

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
            "m_phishingResponse",
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

def playbook_local_local_eh_phishing_generate_drilldowns_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_local_eh_phishing_generate_drilldowns_1() called')
    
    # call playbook "local/eh_phishing_generate_drilldowns", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/eh_phishing_generate_drilldowns", container=container)

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