import oci
import datetime
import subprocess
import json
import requests
import os
import base64


def get_compartments(identity, tenancy_id):
    compartment_ocids = []
    #  Store tenancy id as the first compartment
    compartment_ocids.append(tenancy_id)
    list_compartments_response = oci.pagination.list_call_get_all_results(identity.list_compartments,
                                                                          compartment_id=tenancy_id).data
    for c in list_compartments_response:
        if c.lifecycle_state == "ACTIVE":
            compartment_ocids.append(c.id)
    return compartment_ocids


def retrieve_waf_logs(ELK_index_name, waas, waf_ocid):
    try:
        # convert output into JSON format
        end_time = datetime.datetime.now()
        start_time = end_time + datetime.timedelta(days=-1)
        print(start_time)
        list_waf_logs = waas.list_waf_logs(waf_ocid, time_observed_greater_than_or_equal_to=start_time, limit=49)
        #print(list_waf_logs.__dict__)
        #print(list_waf_logs)
        #print(list_waf_logs.has_next_page)
        #print(list_waf_logs.next_page)

        while list_waf_logs.has_next_page:
            if list_waf_logs.next_page == 2:
                update_ELK(list_waf_logs)
                #update_Splunk(list_waf_logs)
            else:
                list_waf_logs = waas.list_waf_logs(waf_ocid, time_observed_greater_than_or_equal_to=start_time, limit=49, page=list_waf_logs.next_page)
                update_ELK(list_waf_logs)
                #update_Splunk(list_waf_logs)

    except Exception as e:
        print("----------------- Error while retrieving WAF logs -------------------")
        print(e)
        print("-------------------End----------------------")

def update_ELK(list_waf_logs):
    waf_log_output = json.loads(str(list_waf_logs.data))
    # log_types = ["ACCESS", "PROTECTION_RULES", "JS_CHALLENGE", "CAPTCHA", "ACCESS_RULES", "THREAT_FEEDS", "HUMAN_INTERACTION_CHALLENGE", "DEVICE_FINGERPRINT_CHALLENGE", "ADDRESS_RATE_LIMITING"]
    #print(list_waf_logs.data)
    #print(waf_log_output)
    print("count: {}".format(len(waf_log_output)))

    ELK_bulk_format = ''

    for single_usage in range(len(waf_log_output)):
        try:
            # ELK does not WAF timestamp format by default. I am converting it into iso format instead.
            timestamp = waf_log_output[single_usage]['timestamp'][:-6]
            # date_iso_format = datetime.datetime.strptime(timestamp, '%d %b %Y %H:%M:%S').isoformat()
            waf_log_output[single_usage]['timestamp'] = timestamp
            # https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
            # The final line of data must end with a newline character \n.  this step is compulsory to use ELK Bulk API.
            ELK_bulk_format += '{"index": {"_index": "' + ELK_index_name + '"}}' + '\n' + str(waf_log_output[single_usage]).replace("'", '"').replace("[", "").replace("]", "").replace("None","null") + '\n'

        except Exception as e:
            print("----------------- Error while updating ELK-------------------")
            print(e)
            print("-------------------End----------------------")

    print(ELK_bulk_format)
    # push to ELK
    headers = {'Content-type': 'application/json'}
    ELK_url = 'http://ELK_URL:9200/' + ELK_index_name + '/waf/_bulk'
    response = requests.post(url=ELK_url, data=ELK_bulk_format, headers=headers)
    print(response.content)
    print("ELK Bulk is completed and response code: {}".format(response.status_code))


def update_Splunk(list_waf_logs):
    waf_log_output = json.loads(str(list_waf_logs.data))
    # log_types = ["ACCESS", "PROTECTION_RULES", "JS_CHALLENGE", "CAPTCHA", "ACCESS_RULES", "THREAT_FEEDS", "HUMAN_INTERACTION_CHALLENGE", "DEVICE_FINGERPRINT_CHALLENGE", "ADDRESS_RATE_LIMITING"]
    # print(list_waf_logs.data)
    # print(waf_log_output)
    print("count: {}".format(len(waf_log_output)))

    Splunk_bulk_format = ''

    for single_usage in range(len(waf_log_output)):
        try:
            # ELK does not WAF timestamp format by default. I am converting it into iso format instead.
            timestamp = waf_log_output[single_usage]['timestamp'][:-6]
            # date_iso_format = datetime.datetime.strptime(timestamp, '%d %b %Y %H:%M:%S').isoformat()
            waf_log_output[single_usage]['timestamp'] = timestamp
            
            # Splunk HEC
            Splunk_bulk_format += str(
                waf_log_output[single_usage]).replace("'", '"').replace("[", "").replace("]", "").replace("None",
                                                                                                          "null") + '\n'

        except Exception as e:
            print("----------------- Error while updating ELK-------------------")
            print(e)
            print("-------------------End----------------------")

    print(Splunk_bulk_format)
    # push to Splunk
    headers = {'Content-type': 'application/json' , 'Authorization': 'Splunk 50c4c2c8-e087-40e1-a275-############'}
    Splunk_url = 'http://your_URL:8088/services/collector/raw'
    response = requests.post(url=Splunk_url, data=Splunk_bulk_format, headers=headers)
    print(response.content)
    print("data loaging into Splunk is done and response code: {}".format(response.status_code))


if __name__ == "__main__":
    # Get the list of usage reports
    config = oci.config.from_file('config')

    # Initiate the client with the locally available config.
    identity = oci.identity.IdentityClient(config)
    waas = oci.waas.WaasClient(config)
    # signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    # identity = oci.identity.IdentityClient(config={}, signer=signer)

    # Get index name in ELK
    ELK_index_name = config["elk_index_name"]
    # Get WaaS policy ocid
    # waf_ocid = os.environ['waf_ocid']
    waf_ocid = 'ocid1.waaspolicy.YOUR_OCID'
    # tenancy ocid is not required for this case. I only retrieve waf log from the specific waf.

    retrieve_waf_logs(ELK_index_name, waas, waf_ocid)
    print("WAF log has been indexed into ELK!")


