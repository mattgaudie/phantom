def extract_vault_id(container_id=None, **kwargs):
    """
    Extract vault id's as a data path to output to additional blocks.
    
    Args:
        container_id
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.vaultId (CEF type: vault id)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    
    outputs = []
    
    container_data = phantom.get_container(container_id)
    vault_items = phantom.Vault.get_file_info(container_id=container_data['id'])
    phantom.debug(vault_items)
    
    for vault_item in vault_items:
        if vault_item['vault_id'] != None:
            phantom.debug(vault_item['vault_id'])
            outputs.append({"vault_id": vault_item['vault_id']})
            phantom.debug(outputs)
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
