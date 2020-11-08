"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'add_comment_3' block
    add_comment_3(container=container)

    return

def add_comment_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_3() called')

    phantom.comment(container=container, comment="Extracting Email IOCs and conducting reputation lookups")
    cf_local_extract_vault_id_1(container=container)

    return

def extract_email_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('extract_email_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'extract_email_3' call
    formatted_data_1 = phantom.get_format_data(name='format_2')

    parameters = []
    
    # build parameters list for 'extract_email_3' call
    parameters.append({
        'label': "",
        'vault_id': formatted_data_1,
        'container_id': id_value,
        'artifact_name': "Email Artifact",
    })

    phantom.act(action="extract email", parameters=parameters, assets=['msg_parser'], callback=playbook_local_eh_extract_artifact_iocs_1, name="extract_email_3")

    return

def cf_local_extract_vault_id_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_extract_vault_id_1() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        parameters.append({
            'container_id': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/extract_vault_id", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/extract_vault_id', parameters=parameters, name='cf_local_extract_vault_id_1', callback=cf_local_extract_vault_id_1_callback)

    return

def cf_local_extract_vault_id_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('cf_local_extract_vault_id_1_callback() called')
    
    format_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    cf_community_debug_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "cf_local_extract_vault_id_1:custom_function_result.data.*.vault_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    cf_community_debug_2(container=container)
    extract_email_3(container=container)

    return

def cf_community_debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_debug_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_extract_vault_id_1:custom_function_result.data.*.vaultId'], action_results=results )

    parameters = []

    custom_function_result_0_0 = [item[0] for item in custom_function_result_0]

    parameters.append({
        'input_1': custom_function_result_0_0,
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

def playbook_local_eh_extract_artifact_iocs_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_eh_extract_artifact_iocs_1() called')
    
    # call playbook "local/eh_extract_artifact_iocs", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/eh_extract_artifact_iocs", container=container)

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