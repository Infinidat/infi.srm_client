import requests
import xmltodict
import logging
from munch import munchify
from jinja2 import Environment, PackageLoader
from infi.pyutils.contexts import contextmanager
from infi.pyutils.lazy import cached_method

logger = logging.getLogger(__name__)


class SrmClientException(Exception):
    pass


def _listify(value):
    return value if isinstance(value, list) else [value]


def _get_proprety(property_set, name):
    [result] = [value for value in property_set['propSet'] if value['name'] == name]
    return result


class BaseClient(object):
    def _send(self, template, **kwargs):
        xml = self.jinja_env.get_template(template).render(**kwargs)
        logger.info('SENDING:\n%s\n', xml)
        result = self.session.post(self.url, data=xml, verify=False).text
        logger.info('RESULT:\n%s\n', result)
        body = xmltodict.parse(result)['soapenv:Envelope']['soapenv:Body']
        if 'soapenv:Fault' in body:
            raise SrmClientException(body['soapenv:Fault']['faultstring'])
        return body


class SrmClient(BaseClient):
    def __init__(self, hostname, username, password):
        self.url = 'https://%s:9007/' % hostname
        self.username = username
        self.password = password
        self.jinja_env = Environment(loader=PackageLoader('srm_client'))
        self.session = requests.Session() # the session is used to keep vmware's auth cookie
        self.session.headers.update({
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': 'urn:srm0/2.0'
        })

    @contextmanager
    def open(self):
        self._send('SrmLoginLocale.xml', username=self.username, password=self.password)
        try:
            yield self
        finally:
            self._send('SrmLogoutLocale.xml')

    def get_recovery_plans(self):
        """
        Get all recovery plans. Returns a mapping from recovery plan name to a dictionary
        containing its moref, state and list of protection group morefs in this plan.
        """
        data = self._send('ListPlans.xml')
        morefs = [r['#text'] for r in _listify(data['ListPlansResponse'].get('returnval', []))]
        ret = {}
        for moref in morefs:
            data = self._send('RecoveryPlanGetInfo.xml', moref=moref)['RecoveryPlanGetInfoResponse']['returnval']
            groups = [pg['#text'] for pg in _listify(data['protectionGroups'])]
            ret[data['name']] = dict(moref=moref, state=data['state'], groups=groups)
        return ret

    def recovery_start(self, moref, mode):
        assert mode in ('test', 'cleanupTest', 'failover', 'reprotect', 'revert')
        self._send('Start.xml', moref=moref, mode=mode)

    def recovery_cancel(self, moref):
        self._send('Cancel.xml', moref=moref)

    def get_recovery_result(self, moref):
        data = self._send('GetHistory.xml', moref=moref)
        history_moref = data['GetHistoryResponse']['returnval']['#text']
        data = self._send('GetRecoveryResult.xml', moref=history_moref)
        history = data['GetRecoveryResultResponse']['returnval']
        history.pop('key')
        history.pop('plan')
        return history


class vCenterClient(BaseClient):
    def __init__(self, hostname, username, password):
        self.url = 'https://%s/sdk' % hostname
        self.key = None
        self.username = username
        self.password = password
        self.jinja_env = Environment(loader=PackageLoader('srm_client'))
        self.session = requests.Session() # the session is used to keep vmware's auth cookie
        self.session.headers.update({
            'Content-Type': 'text/xml;charset=UTF-8'
        })

    @contextmanager
    def open(self):
        self.key = self._send('Login.xml', username=self.username, password=self.password)['LoginResponse']['returnval']['key']
        try:
            yield self
        finally:
            self._send('Logout.xml')


class InternalSrmClient(BaseClient):
    def __init__(self, hostname, username, password):
        self.url = 'https://%s:%s/dr' % (hostname.split(':')[0], '8095' if ':' not in hostname else hostname.split(':')[1])
        self.username = username
        self.password = password
        self.jinja_env = Environment(loader=PackageLoader('srm_client'))
        self.session = requests.Session() # the session is used to keep vmware's auth cookie
        self.session.headers.update({
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': ''
        })

    @contextmanager
    def _login_to_local_site(self):
        vcenter_address = self._send('RetrieveContent.xml')['RetrieveContentResponse']['returnval']['siteName']
        with vCenterClient(vcenter_address, self.username, self.password).open() as vcenter_client:
            self._send('DrLogin.xml', username=self.username, key=vcenter_client.key)
            yield vcenter_client.key

    @contextmanager
    def _login_to_remote_site(self):
        remote_site = self.get_remote_site()
        with vCenterClient(remote_site['vcenter_address'], self.username, self.password).open() as remote_vcenter_client:
            self._send('LoginRemoteSite.xml', username=self.username, site_id=remote_site['key'], remote_session_id=remote_vcenter_client.key)
            yield

    @contextmanager
    def open(self):
        with self._login_to_local_site(), self._login_to_remote_site():
            try:
                yield self
            finally:
                self._send('DrLogout.xml')

    @contextmanager
    def property_collector(self):
        key = self._send('CreatePropertyCollector.xml')['CreatePropertyCollectorResponse']['returnval']['#text']
        try:
            yield key
        finally:
            self._send('DestroyPropertyCollector.xml', key=key)

    @cached_method
    def get_remote_site(self):
        with self.property_collector() as key:
            response = self._send('RetrievePropertiesEx.xml', key=key,
                                  specSet=[dict(propSet=[dict(type="DrRemoteSite", all=True)],
                                                objectSet=[dict(obj=dict(type="DrServiceInstance", value="DrServiceInstance"), partialUpdates=False,
                                                                selectSet=[dict(type="DrServiceInstance", path="content.remoteSiteManager",
                                                                                selectSet=[dict(type="DrRemoteSiteManager", path="remoteSiteList", selectSet=[])])])])])

        item = munchify(response).RetrievePropertiesExResponse.returnval.objects
        vcenter_address = _get_proprety(item, "name").val['#text']
        srm_server_address = _get_proprety(item, "drServerHost").val['#text']
        srm_server_port = _get_proprety(item, "drServerSoapPort").val['#text']
        return dict(key=item.obj['#text'], vcenter_address=vcenter_address, srm_address="{}:{}".format(srm_server_address, srm_server_port))

    def get_arrays(self):
        with self.property_collector() as key:
            response = self._send('RetrievePropertiesEx.xml', key=key,
                                  specSet=[dict(propSet=[dict(type="DrStorageArrayManager", all=True),
                                                         dict(type="DrStorageReplicatedArrayPair", all=True)],
                                                objectSet=[dict(obj=dict(type="DrReplicationReplicationManager", value="DrReplicationManager"), partialUpdates=False,
                                                                selectSet=[dict(type="DrReplicationReplicationManager", path="replicationProvider", skip=True,
                                                                                selectSet=[dict(type="DrReplicationStorageProvider", path="storageManager", skip=True,
                                                                                                selectSet=[dict(type="DrStorageStorageManager", path="arrayManager",
                                                                                                                selectSet=[dict(type="DrStorageArrayManager", path="arrayPair",
                                                                                                                                selectSet=[])])])])])])])
        arrays = []
        pairs = []

        def _extract_array(item):
            name = _get_proprety(item, 'name').val['#text']
            array_info = _get_proprety(item, 'arrayInfo').val.get('DrStorageArrayInfo', [])
            array_pair = _get_proprety(item, 'arrayPair').val.get('ManagedObjectReference', [])
            pools = [dict(id=array.key, name=array.name, peer_id=array.peerArrayId) for array in _listify(array_info)]
            pairs = [pair['#text'] for pair in _listify(array_pair)]
            arrays.append(dict(key=item.obj['#text'], name=name, pools=pools, pairs=pairs))

        def _extract_pair(item):
            info = _get_proprety(item, 'info').val
            peer = _get_proprety(item, 'peer').val
            device = _get_proprety(item, 'device').val.get('DrStorageStorageDevice', [])
            replicated_datastore = _listify(_get_proprety(item, 'replicatedDatastore').val.get('DrStorageReplicatedDatastore', []))
            devices = [dict(name=device.name, role=device.role, id=device.id) for device in _listify(device)]
            for datastore in replicated_datastore:
                for device in devices:
                    if datastore.extent.device == device['id']:
                        device['key'] = datastore.key['#text']
            pairs.append(dict(key=item.obj['#text'], id=info.key, name=info.name, peer_id=peer.arrayId, devices=devices))

        objects = _listify(munchify(response).RetrievePropertiesExResponse.get('returnval', dict(objects=[]))['objects'])

        for item in objects:
            if item.obj['#text'].startswith('storage-arraymanager'):
                _extract_array(item)
            elif item.obj['#text'].startswith('array-pair'):
                _extract_pair(item)

        for array in arrays:
            for pool in array['pools']:
                try:
                    [active_pair] = [pair for pair in pairs if pair['id'] == pool['id']]
                except ValueError:
                    pool.update(enabled=False, devices=[])
                else:
                    pool.update(enabled=True, **active_pair)
        return arrays

    def refresh_array(self, array):
        self.wait_for_task(self._send("DiscoverArrays_Task.xml", key=array['key']))

        for pool in array['pools']:
            if pool['enabled']:
                self.wait_for_task(self._send("DiscoverDevices_Task.xml", key=pool['key']))

    def enable_array_pair(self, array, pool):
        remote_site = self.get_remote_site()
        self.wait_for_task(self._send("AddArrayPair_Task.xml", key=array['key'],
                           array_id=pool['id'], peer_array_id=pool['peer_id'], site_id=remote_site['key']))

    def disable_array_pair(self, array, pool):
        self.wait_for_task(self._send("RemoveArrayPair_Task.xml", key=array['key'], pair_key=pool['key']))

    def wait_for_task(self, response):
        from time import sleep
        for key, value in response.items():
            if not key.endswith('Response'):
                continue
            if '#text' in value['returnval']:
                task_key = value['returnval']['#text']
            else:
                for key, obj in value['returnval'].items():
                    if key.endswith('Task') and '#text' in obj:
                        task_key = obj['#text']

        specSet = [dict(propSet=[dict(type="Task", all=True)],
                        objectSet=[dict(obj=dict(type="Task", value=task_key), partialUpdates=False, selectSet=[])])]

        state = 'queued'
        with self.property_collector() as property_collector_key:
            while state not in ('success', 'error'):
                response = munchify(self._send('RetrievePropertiesEx.xml', key=property_collector_key, specSet=specSet))
                item = _listify(response.RetrievePropertiesExResponse.returnval.objects)[0]
                state = _get_proprety(item, 'info').val.state
                sleep(1)

        if state in ('error',):
            raise SrmClientException(item.propSet[1].val.error.localizedMessage)

    def get_protection_groups(self):
        with self.property_collector() as key:
            response = self._send('RetrievePropertiesEx.xml', key=key,
                                  specSet=[dict(propSet=[dict(type="DrReplicationProtectionGroup", all=True),
                                                         dict(type="DrReplicationProtectedVm", all=True)],
                                                objectSet=[dict(obj=dict(type="DrReplicationReplicationManager", value="DrReplicationManager"), partialUpdates=False,
                                                                selectSet=[dict(type="DrReplicationReplicationManager", path="protectionGroupFolder",
                                                                                selectSet=[dict(type="DrFolder", path="childEntity", name="toPg",
                                                                                                selectSet=[dict(name="toPg"),
                                                                                                           dict(type="DrReplicationProtectionGroup", path="protectedVm")])])])])])

        objects = _listify(munchify(response).RetrievePropertiesExResponse.get('returnval', dict(objects=[]))['objects'])
        protection_groups = []
        protected_vms = {}

        def _extract_protection_group(item):
            protection_groups.append(dict(key=item.obj['#text'], name=_get_proprety(item, 'settings').val.name,
                                          state=_get_proprety(item, 'state').val['#text'],
                                          protected_datastores=[dict(key=value.protectedDatastore['#text'], name=value.protectedName) for
                                                                     value in _listify(_get_proprety(item, 'peer').val.providerDetails.datastore)],
                                          protected_vms=[dict(key=vm['#text'], name=protected_vms[vm['#text']]['name']) for
                                                         vm in _listify(_get_proprety(item, 'protectedVm').val.get('ManagedObjectReference', []))]))

        def _extract_protected_vm(item):
            protected_vms[item.obj['#text']] = dict(key=item.obj['#text'],
                                                    state=_get_proprety(item, 'state').val['#text'],
                                                    name=_get_proprety(item, 'productionVmInfo').val.name,
                                                    protection_group=_get_proprety(item, 'parent').val['#text'])

        for item in objects:
            if item.obj['#text'].startswith('protected-vm'):
                _extract_protected_vm(item)
        for item in objects:
            if item.obj['#text'].startswith('protection-group'):
                _extract_protection_group(item)

        return protection_groups

    def delete_protection_group(self, group):
        self.wait_for_task(self._send('UnprotectAndRemoveProtectionGroup.xml', key=group['key']))

    def create_protection_group(self, group, datastores):
        self.wait_for_task(self._send('CreateProtectionGroup_Task.xml', name=group,
                                      datastores=datastores, site_id=self.get_remote_site()['key']))
        [protection_group] = [item for item in self.get_protection_groups() if item['name'] == group]
        vms = []
        for datastores in datastores:
            vms.extend(datastores['vms'])
        self._send('ProtectVms.xml', key=protection_group['key'], vms=vms)

    def get_unprotected_datastores(self):
        datastores = []
        unassigned_groups = munchify(self._send('QueryUnassignedDatastoreGroupArrays.xml'))
        for array in _listify(unassigned_groups.QueryUnassignedDatastoreGroupArraysResponse.get('returnval', [])):
            unassigned_datastores = munchify(self._send('QueryUnassignedDatastoreGroups.xml', key=array['#text']))
            for datastore_group in _listify(unassigned_datastores.QueryUnassignedDatastoreGroupsResponse.get('returnval', [])):
                datastores.append(dict(key=datastore_group.key, vms=[vm.key['#text'] for vm in  _listify(datastore_group.vm)]))
        for array in self.get_arrays():
            for pool in array['pools']:
                if pool['enabled']:
                    for device in pool['devices']:
                        for datastore in datastores:
                            if 'key' in device and device['key'] == datastore['key']:
                                datastore['name'] = device['name']
                                datastore['pair'] = pool['key']
        return datastores

    def delete_recovery_plan(self, plan):
        # we fetch the recovery plan ref from the public api
        self.wait_for_task(self._send('DestroyRecoveryPlan_Task.xml', key=plan['moref'].replace('srm-recovery-plan', 'recovery-plan')))

    def create_recovery_plan(self, plan, protection_groups):
        self.wait_for_task(self._send('CreateRecoveryPlan_Task.xml', name=plan, protection_groups=protection_groups))

    def get_adapters(self):
        with self.property_collector() as key:
            response = self._send('RetrievePropertiesEx.xml', key=key,
                                  specSet=[dict(propSet=[dict(type="DrStorageStorageAdapter", all=True)],
                                                objectSet=[dict(obj=dict(type="DrReplicationReplicationManager", value="DrReplicationManager"), partialUpdates=False,
                                                                selectSet=[dict(type="DrReplicationReplicationManager", path="replicationProvider", skip=True,
                                                                                selectSet=[dict(type="DrReplicationStorageProvider", path="storageManager", skip=True,
                                                                                                selectSet=[dict(type="DrStorageStorageManager", path="adapter")])])])])])
        objects = _listify(response['RetrievePropertiesExResponse'].get('returnval', dict(objects=[]))['objects'])
        adapters = []
        for item in objects:
            model = _listify(_get_proprety(item, 'arrayModel')['val'].get('DrStorageStorageAdapterArrayModel', []))[0]
            info = _get_proprety(item, 'info')['val']
            software = _listify(_get_proprety(item, 'replicationSoftware')['val'].get('DrStorageStorageAdapterReplicationSoftware', []))[0]
            connection = _listify(_get_proprety(item, 'connectionPrompt')['val'].get('DrStorageAdapterConnectionPrompt', []))[0]
            parameters = [key if 'key' not in value else '%s.%s' % (key, value['key']) for
                          key, value in connection.items()[2:]]
            adapters.append(dict(key=item['obj']['#text'], model=model['name'], vendor=model['vendor']['text'],
                                 version=info['version'], name=software['name'],
                                 connection_parameters=parameters))
        return adapters

    def create_array(self, adapter, name, connection_parameters):
        self.wait_for_task(self._send('StorageManagerCreateArrayManager2_Task.xml',
                                      key=adapter['key'], name=name, connection_parameters=connection_parameters))

    def delete_array(self, adapter):
        self.wait_for_task(self._send('StorageManagerDeleteArrayManager2_Task.xml', key=adapter['key']))
