"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_community_list_drop_none_2' block
    cf_community_list_drop_none_2(container=container)

    # call 'cf_community_list_drop_none_1' block
    cf_community_list_drop_none_1(container=container)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_1() called')
    
    template = """https://es-nswhealth.splunkcloud.com/en-GB/app/SplunkEnterpriseSecuritySuite/email_search?form.sender={0}&earliest=-24h%40h"""

    # parameter list for template variable replacement
    parameters = [
        "cf_community_list_drop_none_1:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    cf_community_debug_1(container=container)
    join_format_5(container=container)

    return

def cf_community_debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_debug_1() called')
    
    formatted_data_0 = [
        [
            phantom.get_format_data(name="format_1"),
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
    phantom.custom_function(custom_function='community/debug', parameters=parameters, name='cf_community_debug_1')

    return

def cf_community_list_drop_none_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_list_drop_none_1() called')
    
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
    phantom.custom_function(custom_function='community/list_drop_none', parameters=parameters, name='cf_community_list_drop_none_1', callback=cf_community_list_drop_none_1_callback)

    return

def cf_community_list_drop_none_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('cf_community_list_drop_none_1_callback() called')
    
    format_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    format_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def cf_community_list_drop_none_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_list_drop_none_2() called')
    
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
    phantom.custom_function(custom_function='community/list_drop_none', parameters=parameters, name='cf_community_list_drop_none_2', callback=format_3)

    return

def cf_local_url_encode_string_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_url_encode_string_1() called')
    
    formatted_data_0 = [
        [
            phantom.get_format_data(name="format_3"),
        ],
    ]

    parameters = []

    for item0 in formatted_data_0:
        parameters.append({
            'input_string': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/url_encode_string", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/url_encode_string', parameters=parameters, name='cf_local_url_encode_string_1', callback=format_2)

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """https://es-nswhealth.splunkcloud.com/en-GB/app/SplunkEnterpriseSecuritySuite/email_search?form.subject={0}&earliest=-24h%40h"""

    # parameter list for template variable replacement
    parameters = [
        "cf_local_url_encode_string_1:custom_function_result.data.url_string",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    cf_community_debug_2(container=container)
    join_format_5(container=container)

    return

def cf_community_debug_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_debug_2() called')
    
    formatted_data_0 = [
        [
            phantom.get_format_data(name="format_2"),
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
    phantom.custom_function(custom_function='community/debug', parameters=parameters, name='cf_community_debug_2')

    return

def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_3() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "cf_community_list_drop_none_2:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    cf_local_url_encode_string_1(container=container)

    return

def format_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_5() called')
    
    template = """Sender: [{2}]({0})
Subject: [{3}]({1})
File Hash:[f48c5e053a8adf1fbfb5899ef93fea91dadac912](https://es-nswhealth.splunkcloud.com/en-GB/app/SplunkEnterpriseSecuritySuite/email_search?form.attach_hash=f48c5e053a8adf1fbfb5899ef93fea91dadac912&earliest=-24h%40h)
File Hash: [8dcb2a8c7fd97768443d0754aa49989a296ed9b2](https://es-nswhealth.splunkcloud.com/en-GB/app/SplunkEnterpriseSecuritySuite/email_search?form.attach_hash=8dcb2a8c7fd97768443d0754aa49989a296ed9b2&earliest=-24h%40h)"""

    # parameter list for template variable replacement
    parameters = [
        "format_1:formatted_data",
        "format_2:formatted_data",
        "format_6:formatted_data",
        "format_3:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_5")

    add_note_2(container=container)

    return

def join_format_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_5() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(custom_function_names=['cf_community_list_drop_none_1', 'cf_local_url_encode_string_1']):
        
        # call connected block "format_5"
        format_5(container=container, handle=handle)
    
    return

def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_2() called')

    formatted_data_1 = phantom.get_format_data(name='format_5')

    note_title = "Investigative Searches"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def format_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_6() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "cf_community_list_drop_none_1:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_6")

    join_format_5(container=container)

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