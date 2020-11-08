"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_local_create_current_epoch_time_1' block
    cf_local_create_current_epoch_time_1(container=container)

    # call 'filter_5' block
    filter_5(container=container)

    # call 'filter_4' block
    filter_4(container=container)

    # call 'filter_3' block
    filter_3(container=container)

    # call 'filter_2' block
    filter_2(container=container)

    # call 'filter_1' block
    filter_1(container=container)

    return

def post_data_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('post_data_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'post_data_2' call
    formatted_data_1 = phantom.get_format_data(name='format_3')

    parameters = []
    
    # build parameters list for 'post_data_2' call
    parameters.append({
        'data': formatted_data_1,
        'host': "ehealth-nsw-phantom",
        'index': "phantom_notable",
        'source': "phantom",
        'source_type': "phantom:notable",
    })

    phantom.act(action="post data", parameters=parameters, assets=['enterprise security'], name="post_data_2")

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_1() called')
    
    template = """index=esa_summary_index  earliest=-14d@d \"{0}\"
| stats values(sender) as _raw"""

    # parameter list for template variable replacement
    parameters = [
        "cf_community_list_drop_none_1:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    run_query_1(container=container)

    return

def cf_community_list_drop_none_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_list_drop_none_1() called')
    
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
    phantom.custom_function(custom_function='community/list_drop_none', parameters=parameters, name='cf_community_list_drop_none_1', callback=cf_community_list_drop_none_1_callback)

    return

def cf_community_list_drop_none_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('cf_community_list_drop_none_1_callback() called')
    
    format_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    format_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.emailHeaders.Subject", "!=", None],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        cf_community_list_drop_none_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        cf_community_list_drop_none_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """index=esa_summary_index earliest=-14d@d \"{0}\"
| stats values(recipient) as recipients
| eval _raw=mvjoin(recipients, \"|\")
| fields _raw"""

    # parameter list for template variable replacement
    parameters = [
        "cf_community_list_drop_none_1:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    run_query_2(container=container)

    return

def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_query_1' call
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'run_query_1' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['enterprise security'], callback=run_query_1_callback, name="run_query_1")

    return

def run_query_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('run_query_1_callback() called')
    
    cf_community_debug_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    format_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def run_query_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_query_2' call
    formatted_data_1 = phantom.get_format_data(name='format_2')

    parameters = []
    
    # build parameters list for 'run_query_2' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['enterprise security'], callback=run_query_2_callback, name="run_query_2")

    return

def run_query_2_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('run_query_2_callback() called')
    
    cf_community_debug_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    format_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_3() called')
    
    template = """{7} title=\"Phishing Email Detected by User Submission\", subject=\"{0}\", sender=\"{1}\", recipient=\"{2}\", url=\"{3}\", dest=\"{4}\", dest_dns=\"{5}\", file_hash=\"{6}\""""

    # parameter list for template variable replacement
    parameters = [
        "cf_community_list_drop_none_1:custom_function_result.data.*.item",
        "format_5:formatted_data",
        "format_6:formatted_data",
        "format_4:formatted_data",
        "format_7:formatted_data",
        "format_8:formatted_data",
        "format_9:formatted_data",
        "format_10:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    cf_community_debug_3(container=container)
    format_12(container=container)

    return

def join_format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_3() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['run_query_2', 'run_query_1'], custom_function_names=['cf_local_create_current_epoch_time_1']):
        
        # call connected block "format_3"
        format_3(container=container, handle=handle)
    
    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_4() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_4")

    join_format_3(container=container)

    return

def cf_community_debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_debug_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['run_query_1:action_result.data.*._raw', 'run_query_1:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    action_results_data_0_0 = [item[0] for item in action_results_data_0]

    parameters.append({
        'input_1': action_results_data_0_0,
        'input_2': None,
        'input_3': None,
        'input_4': None,
        'input_5': None,
        'input_6': None,
        'input_7': None,
        'input_8': None,
        'input_9': None,
        'input_10': None,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/debug", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/debug', parameters=parameters, name='cf_community_debug_1')

    return

def cf_community_debug_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_debug_2() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['run_query_2:action_result.data.*._raw', 'run_query_2:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    action_results_data_0_0 = [item[0] for item in action_results_data_0]

    parameters.append({
        'input_1': action_results_data_0_0,
        'input_2': None,
        'input_3': None,
        'input_4': None,
        'input_5': None,
        'input_6': None,
        'input_7': None,
        'input_8': None,
        'input_9': None,
        'input_10': None,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/debug", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/debug', parameters=parameters, name='cf_community_debug_2')

    return

def cf_community_debug_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_debug_3() called')
    
    formatted_data_0 = [
        [
            phantom.get_format_data(name="format_3"),
        ],
    ]

    parameters = []

    formatted_data_0_0 = [item[0] for item in formatted_data_0]

    parameters.append({
        'input_1': formatted_data_0_0,
        'input_2': None,
        'input_3': None,
        'input_4': None,
        'input_5': None,
        'input_6': None,
        'input_7': None,
        'input_8': None,
        'input_9': None,
        'input_10': None,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/debug", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/debug', parameters=parameters, name='cf_community_debug_3')

    return

def format_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_5() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "run_query_1:action_result.data.*._raw",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_5")

    join_format_3(container=container)

    return

def format_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_6() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "run_query_2:action_result.data.*._raw",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_6")

    join_format_3(container=container)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_7(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_7() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_3:condition_1:artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_7")

    join_format_3(container=container)

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_8(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_8() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_4:condition_1:artifact:*.cef.destinationDnsDomain",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_8")

    join_format_3(container=container)

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHashSha1", "!=", ""],
        ],
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_9(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_9() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_5:condition_1:artifact:*.cef.fileHashSha1",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_9")

    join_format_3(container=container)

    return

def cf_local_create_current_epoch_time_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_create_current_epoch_time_1() called')
    
    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/create_current_epoch_time", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/create_current_epoch_time', parameters=parameters, name='cf_local_create_current_epoch_time_1', callback=format_10)

    return

def format_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_10() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "cf_local_create_current_epoch_time_1:custom_function_result.data.epoch_time",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_10")

    cf_community_debug_4(container=container)
    join_format_3(container=container)

    return

def cf_community_debug_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_debug_4() called')
    
    formatted_data_0 = [
        [
            phantom.get_format_data(name="format_10"),
        ],
    ]

    parameters = []

    formatted_data_0_0 = [item[0] for item in formatted_data_0]

    parameters.append({
        'input_1': formatted_data_0_0,
        'input_2': None,
        'input_3': None,
        'input_4': None,
        'input_5': None,
        'input_6': None,
        'input_7': None,
        'input_8': None,
        'input_9': None,
        'input_10': None,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/debug", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/debug', parameters=parameters, name='cf_community_debug_4')

    return

def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_1() called')

    note_title = "Notable Created in Enterprise Security"
    note_content = "A notable event containing relevant information about this event has been created in Enterprise Security."
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def Notable_Creation_Approval_Request(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Notable_Creation_Approval_Request() called')
    
    # set user and message variables for phantom.prompt call
    user = "Incident Commander"
    message = """You have received the following request: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "format_12:formatted_data",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Notable_Creation_Approval_Request", parameters=parameters, response_types=response_types, callback=Notable_Creation_Approval_Request_callback)

    return

def Notable_Creation_Approval_Request_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('Notable_Creation_Approval_Request_callback() called')
    
    post_data_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    add_note_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_12() called')
    
    template = """A notable event creation is being requested for the investigation \"{0}\" to assist with ongoing activities. Please confirm yes or no."""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_12")

    Notable_Creation_Approval_Request(container=container)

    return

def cf_community_list_drop_none_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_list_drop_none_2() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.emailHeaders.X-Envelope-From', 'artifact:*.id'])

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
    phantom.custom_function(custom_function='community/list_drop_none', parameters=parameters, name='cf_community_list_drop_none_2')

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