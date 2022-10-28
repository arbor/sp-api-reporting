from datetime import datetime, timedelta
import logging
import requests
import urllib.parse

# File constants
MINUTES_PER_DAY = 1440

# - CERT handling
CERT_verify = False # False or cert file
if CERT_verify == False:
	import urllib3
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
 
class SPClient:
    
    def __init__(self, url, api_key):
        self.url = url
        self.api_key = api_key
        self.sl_conn = None
        self.perPage = "perPage=50" # default: "perPage=50"
            
    def api_request(self, uri, key, body=None):
        api_response = None
        
        retry_cnt = 0
        request_OK = False
        
        while not request_OK:
            retry_cnt += 1
            try:
                if body is None:
                    api_response = requests.get(uri, 
                                                headers={'X-Arbux-APIToken': self.api_key,
                                                         'Content-Type': 'application/vnd.api+json'}, verify=CERT_verify, timeout=(15,90))
                else:
                    api_response = requests.post(uri, data=body, headers={'X-Arbux-APIToken': key, 'Content-Type': 'application/vnd.api+json'}, verify=CERT_verify, timeout=(15,90))
                request_OK = True
            except requests.exceptions.RequestException as e:
                logging.info('')
                logging.info(e)
                if retry_cnt < 3:
                    logging.info('... trying again')
                else:
                    logging.info('... giving up and exit !!')
                    exit(1)
        
        # Handle any API error responses
        if (api_response.status_code < requests.codes.ok or api_response.status_code >= requests.codes.multiple_choices):
            print("API responded with this error: \n{}".format(api_response.text))
            return []

        api_response = api_response.json()
        return api_response



    def get_alerts(self, start_time = None, minutes_ago=30*MINUTES_PER_DAY, alert_id = None):
        if not start_time:
            now = datetime.utcnow()
            start_datetime = now - timedelta(minutes=minutes_ago)
            start_time = start_datetime.isoformat()
        if alert_id:
            logging.info('### Alert retrieval - ID: ' + str(alert_id))
        else:
            logging.info('### Alert retrieval')
            
        if alert_id != None:
            URI = "/api/sp/alerts/{}".format(alert_id)
            URL = "https://" + self.url + URI
        else:
            URI = "/api/sp/alerts/?" + self.perPage + "&filter="
            # start_time = '2022-10-20T12:00:00Z' # for testing to limit runtime just fetching some alerts
            # stop_time = '2022-10-21T00:00:00Z' # for testing to limit runtime just fetching some alerts
            FILTERs = 	['/data/attributes/alert_class=dos',
                        #'/data/attributes/alert_type=dos_host_detection', # for testing to limit runtime just fetching some alerts
                        '/data/attributes/start_time>' + start_time,
                        # '/data/attributes/stop_time<' + stop_time # for testing to limit runtime just fetching some alerts
                        ]
            if alert_id != None:
                FILTERs += ['/data/id={}'.format(alert_id)]
            FILTER = ' AND '.join(FILTERs)
            FILTER = urllib.parse.quote(FILTER, safe='')
            api_page = 1
            URL = "https://" + self.url + URI + FILTER + "&page={}".format(api_page)
        
        logging.info('## retrieving alerts: 0%')	

        api_response = self.api_request(URL, self.api_key)
        
        if api_response != []:
            if alert_id == None:
                api_data = api_response['data']
            else:
                api_data = [api_response['data']]
                
            if 'pagination' in api_response['meta']:
                api_page_last = api_response['meta']['pagination']['totalPages']
            else:
                api_page_last = None
            
            #if (api_page_last != None and api_page_last > 20): # for testing to limit runtime just fetching some alerts
            #	api_page_last = 1
            
            if api_page_last != None:
                for api_page in range(2,api_page_last+1):
                    URL = "https://" + self.url + URI + FILTER + "&page={}".format(api_page)
                    api_response = self.api_request(URL, self.api_key)
                    api_data.extend(api_response['data'])
                    logging.info(' {:.1f}%'.format((api_page/api_page_last)*100))
            
            if (api_page_last == None or api_page_last == 1):
                logging.info(' 100% DONE')
            else:
                logging.info(' DONE')
            
            if alert_id == None:
                logging.info('## Alert count: {}'.format(len(api_data)))
        else:
            api_data = []
        
        alert_data = api_data
        
        # count alerts with mitigations
        alerts_with_mitigations = 0
        for alert in alert_data:
            if 'mitigation' in alert['relationships']:
                alerts_with_mitigations +=1
        alerts_mitigation_cnt = 0
        
        # check for associated mitigations
        alert_mitigations = {}
        for alert in alert_data:
            tms_mitigation_id_list = []
            fs_mitigation_id_list = []
            bh_mitigation_id_list = []
            
            alert_mitigations_temp = {}
            start_time = alert['attributes']['start_time'].split('+')[0] + 'Z'
            stop_time = alert['attributes'].get('stop_time', datetime.utcnow().isoformat().split('.')[0]).split('+')[0] + 'Z'
            
            if 'mitigation' in alert['relationships']:
                alerts_mitigation_cnt +=1
                logging.info(' + {}/{} - Alert Mitigation information retrieval for AlertID: {}'.format(alerts_mitigation_cnt, alerts_with_mitigations, alert['id']))
                for mitigation in alert['relationships']['mitigation']['data']:
                    alert_mitigations_temp[mitigation['id']] = {'alert_id': alert['id'], 'mitigation_id': mitigation['id'], 'data': None, 'dropped_traffic_rates': None}
                    alert_mitigations_temp[mitigation['id']]['data'] = self.get_mitigation_data(mitigation['id'])
                    if 'tms' in mitigation['id']:
                        tms_mitigation_id_list.append(mitigation['id'])
                    if 'flowspec' in mitigation['id']:
                        fs_mitigation_id_list.append(mitigation['id'])
                    if 'blackhole' in mitigation['id']:
                        bh_mitigation_id_list.append(mitigation['id'])

            if tms_mitigation_id_list != []:
                for tms_mitigation_id in tms_mitigation_id_list:
                    alert_mitigations_temp[tms_mitigation_id]['dropped_traffic_rates'] = self.get_tms_mitigation_rates(tms_mitigation_id, start_time, stop_time)
            
            if fs_mitigation_id_list != []:
                fs_mitigation_rates = self.get_alert_fs_mitigation_rates(alert['id'], fs_mitigation_id_list, start_time, stop_time)
                for fs_mitigation_id in fs_mitigation_rates:
                    alert_mitigations_temp[fs_mitigation_id]['dropped_traffic_rates'] = fs_mitigation_rates[fs_mitigation_id]
            
            if bh_mitigation_id_list != []:
                bh_mitigation_rates = self.get_alert_bh_mitigation_rates(alert['id'], bh_mitigation_id_list, start_time, stop_time)
                # create fake BH mitigation with data from first actuall BH mitigation
                fake_bh_id = 'blackhole-fake4rates-'+str(alert['id'])
                alert_mitigations_temp[fake_bh_id] = {'alert_id': alert['id'], 'mitigation_id': fake_bh_id, 'data': None, 'dropped_traffic_rates': None}
                alert_mitigations_temp[fake_bh_id]['data'] = alert_mitigations_temp[bh_mitigation_id_list[0]]['data']
                
                for bh_mitigation_id in bh_mitigation_rates:
                    alert_mitigations_temp[bh_mitigation_id]['dropped_traffic_rates'] = bh_mitigation_rates[bh_mitigation_id]

            if alert_mitigations_temp != {}:
                alert_mitigations[alert['id']] = alert_mitigations_temp

        return [alert_data, alert_mitigations]



    def get_alert_bh_mitigation_rates(self, alert_id, bh_list, timeseries_start, timeseries_end):
        alert_id = str(alert_id)
        
        logging.info(' +++ Blackhole mitigation rate retrieval - Alert ID: ' + alert_id + ' ...')
        URI = "/api/sp/alerts/{}/traffic/misuse_types/?query_unit=bps&query_view=blackhole&timeseries_end={}&timeseries_start={}".format(alert_id, timeseries_end, timeseries_start)

        URL = "https://" + self.url + URI
        api_response = self.api_request(URL, self.api_key)
        api_data_bps = api_response['data']
        
        URI = "/api/sp/alerts/{}/traffic/misuse_types/?query_unit=pps&query_view=blackhole&timeseries_end={}&timeseries_start={}".format(alert_id, timeseries_end, timeseries_start)
        URL = "https://" + self.url + URI
        api_response = self.api_request(URL, self.api_key)
        api_data_pps = api_response['data']
        
        fake_bh_id = 'blackhole-fake4rates-'+alert_id
        
        drop_rates_dict = { fake_bh_id: {'bps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}, 'pps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}}}
        
        for data in api_data_bps:
            if 'misuse_types-7' in data.get('id'):
                bps_data = data['attributes']['view']['blackhole']['unit']['bps']
                drop_rates_dict[fake_bh_id]['bps']['step'] = bps_data['step']
                drop_rates_dict[fake_bh_id]['bps']['timeseries_start'] = bps_data['timeseries_start']
                drop_rates_dict[fake_bh_id]['bps']['average'] = bps_data['avg_value']
                drop_rates_dict[fake_bh_id]['bps']['max'] = bps_data['max_value']
                drop_rates_dict[fake_bh_id]['bps']['timeseries'] = bps_data['timeseries']
        
        for data in api_data_pps:
            if 'misuse_types-7' in data.get('id'):
                pps_data = data['attributes']['view']['blackhole']['unit']['pps']
                drop_rates_dict[fake_bh_id]['pps']['step'] = pps_data['step']
                drop_rates_dict[fake_bh_id]['pps']['timeseries_start'] = pps_data['timeseries_start']
                drop_rates_dict[fake_bh_id]['pps']['average'] = pps_data['avg_value']
                drop_rates_dict[fake_bh_id]['pps']['max'] = pps_data['max_value']
                drop_rates_dict[fake_bh_id]['pps']['timeseries'] = pps_data['timeseries']
                
        for bh_mit in bh_list:
            drop_rates_dict[bh_mit] = {'bps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}, 'pps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}}

        logging.info(' DONE')
        
        return drop_rates_dict



    def get_alert_fs_mitigation_rates(self, alert_id, fs_list, timeseries_start, timeseries_end):
        logging.info(' +++ Flowpsec mitigation rate retrieval - Alert ID: ' + str(alert_id) + ' ...')

        URI = "/api/sp/alerts/{}/traffic/flowspecs/?query_unit=bps&query_view=flowspec&timeseries_end={}&timeseries_start={}".format(alert_id, timeseries_end, timeseries_start)
        URL = "https://" + self.url + URI
        api_response = self.api_request(URL, self.api_key)
        api_data_bps = api_response['data']
        
        URI = "/api/sp/alerts/{}/traffic/flowspecs/?query_unit=pps&query_view=flowspec&timeseries_end={}&timeseries_start={}".format(alert_id, timeseries_end, timeseries_start)
        URL = "https://" + self.url + URI
        api_response = self.api_request(URL, self.api_key)
        api_data_pps = api_response['data']
        
        fs_data_temp = {}
        
        for fs in api_data_bps:
            fs_id = fs['relationships']['mitigation']['data']['id']
            fs_data_temp[fs_id] = {'bps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}, 'pps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}}
            bps_data = fs['attributes']['view']['flowspec']['unit']['bps']
            fs_data_temp[fs_id]['bps']['step'] = bps_data['step']
            fs_data_temp[fs_id]['bps']['timeseries_start'] = bps_data['timeseries_start']
            fs_data_temp[fs_id]['bps']['average'] = bps_data['avg_value']
            fs_data_temp[fs_id]['bps']['max'] = bps_data['max_value']
            fs_data_temp[fs_id]['bps']['timeseries'] = bps_data['timeseries']
        
        for fs in api_data_pps:
            fs_id = fs['relationships']['mitigation']['data']['id']
            if fs_id not in fs_data_temp:
                fs_data_temp[fs_id] = {'bps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}, 'pps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}}
            pps_data = fs['attributes']['view']['flowspec']['unit']['pps']
            fs_data_temp[fs_id]['pps']['step'] = pps_data['step']
            fs_data_temp[fs_id]['pps']['timeseries_start'] = pps_data['timeseries_start']
            fs_data_temp[fs_id]['pps']['average'] = pps_data['avg_value']
            fs_data_temp[fs_id]['pps']['max'] = pps_data['max_value']
            fs_data_temp[fs_id]['pps']['timeseries'] = pps_data['timeseries']
        
        drop_rates_dict = {}
        for fs_mit in fs_list:
            if fs_mit in fs_data_temp:
                drop_rates_dict[fs_mit] = fs_data_temp[fs_mit]
            else:
                drop_rates_dict[fs_mit] = {'bps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}, 'pps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}}
        
        logging.info(' DONE')
        
        return drop_rates_dict



    def get_tms_mitigation_rates(self, mitigation_id, timeseries_start, timeseries_end):
        logging.info(' +++ TMS mitigation rate retrieval - ID: ' + str(mitigation_id) + ' ...')
        
        URI = "/api/sp/mitigations/{}/rates_all_devices?timeseries_end={}&timeseries_start={}".format(mitigation_id, timeseries_end, timeseries_start )
        URL = "https://" + self.url + URI
        api_response = self.api_request(URL, self.api_key)
        
        try:
            api_data = api_response['data']['attributes']
        except:
            print('!! ERROR !! -> API - URI: ')
            print(URI)
            print('')
            api_data = {}
        
        drop_rates = {'bps': {'timeseries_start': None, 'step': None}, 'pps': {'timeseries_start': None, 'step': None}}
        
        drop_rates['bps']['average'] = api_data.get('total', {}).get('drop', {}).get('bps', {}).get('average')
        drop_rates['bps']['max'] = api_data.get('total', {}).get('drop', {}).get('bps', {}).get('max')
        drop_rates['bps']['timeseries'] = api_data.get('total', {}).get('drop', {}).get('bps', {}).get('timeseries')
        if drop_rates['bps']['timeseries'] != None:
            drop_rates['bps']['timeseries_start'] = api_data['timeseries_start']
            drop_rates['bps']['step'] = api_data['step']
            
        drop_rates['pps']['average'] = api_data.get('total', {}).get('drop', {}).get('pps', {}).get('average')
        drop_rates['pps']['max'] = api_data.get('total', {}).get('drop', {}).get('pps', {}).get('max')
        drop_rates['pps']['timeseries'] = api_data.get('total', {}).get('drop', {}).get('pps', {}).get('timeseries')
        if drop_rates['pps']['timeseries'] != None:
            drop_rates['pps']['timeseries_start'] = api_data['timeseries_start']
            drop_rates['pps']['step'] = api_data['step']
            
        logging.info(' DONE')
        
        return drop_rates



    def get_mitigation_data(self, mitigation_id):
        logging.info(' +++ mitigation data retrieval - Mitigation ID: ' + str(mitigation_id) + ' ...')

        URI = "/api/sp/mitigations/{}".format(mitigation_id) 
        URL = "https://" + self.url + URI
        api_response = self.api_request(URL, self.api_key)
        
        api_data = api_response['data']
        logging.info('DONE')

        return api_data



    def get_managed_objects(self):
        logging.info('### Managed Objects retrieval')
        
        URI = "/api/sp/managed_objects/?" + self.perPage
        URL = "https://" + self.url + URI
        
        logging.info('## retrieving managed objects: 0%')	
        
        api_response = self.api_request(URL, self.api_key)
        
        api_data = api_response['data']
        
        if 'pagination' in api_response['meta']:
            api_page_last = api_response['meta']['pagination']['totalPages']
        else:
            api_page_last = None
        
        if api_page_last != None:
            for api_page in range(2,api_page_last+1):
                URL = "https://" + self.url + URI + "&page={}".format(api_page)
                api_response = self.api_request(URL, self.api_key)
                api_data.extend(api_response['data'])
                logging.info(' {:.1f}%'.format((api_page/api_page_last)*100))
        
        if (api_page_last == None or api_page_last == 1):
            logging.info(' 100% DONE')
        else:
            logging.info(' DONE')

        logging.info('## Managed Object count: {}'.format(len(api_data)))
        return api_data
