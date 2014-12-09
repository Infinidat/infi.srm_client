import requests
from jinja2 import Environment, PackageLoader
import xmltodict
from infi.pyutils.contexts import contextmanager
import logging

logger = logging.getLogger(__name__)


class SrmClientException(Exception):
    pass


def _listify(value):
    return value if isinstance(value, list) else [value]


class SrmClient(object):
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

    def _send(self, template, **kwargs):
        xml = self.jinja_env.get_template(template).render(**kwargs)
        logger.info('SENDING:\n%s\n', xml)
        result = self.session.post(self.url, data=xml, verify=False).text
        logger.info('RESULT:\n%s\n', result)
        body = xmltodict.parse(result)['soapenv:Envelope']['soapenv:Body']
        if 'soapenv:Fault' in body:
            raise SrmClientException(body['soapenv:Fault']['faultstring'])
        return body

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
        morefs = [r['#text'] for r in _listify(data['ListPlansResponse']['returnval'])]
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


class vCenterClient(object):
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

    def _send(self, template, **kwargs):
        xml = self.jinja_env.get_template(template).render(**kwargs)
        logger.info('SENDING:\n%s\n', xml)
        result = self.session.post(self.url, data=xml, verify=False).text
        logger.info('RESULT:\n%s\n', result)
        body = xmltodict.parse(result)['soapenv:Envelope']['soapenv:Body']
        if 'soapenv:Fault' in body:
            raise SrmClientException(body['soapenv:Fault']['faultstring'])
        return body

    @contextmanager
    def open(self):
        self.key = self._send('Login.xml', username=self.username, password=self.password)['LoginResponse']['returnval']['key']
        try:
            yield self
        finally:
            self._send('Logout.xml')


class InternalSrmClient(object):
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

    def _send(self, template, **kwargs):
        xml = self.jinja_env.get_template(template).render(**kwargs)
        logger.info('SENDING:\n%s\n', xml)
        result = self.session.post(self.url, data=xml, verify=False).text
        logger.info('RESULT:\n%s\n', result)
        body = xmltodict.parse(result)['soapenv:Envelope']['soapenv:Body']
        if 'soapenv:Fault' in body:
            raise SrmClientException(body['soapenv:Fault']['faultstring'])
        return body

    @contextmanager
    def open(self):
        vcenter_address = self._send('RetrieveContent.xml')['RetrieveContentResponse']['returnval']['siteName']
        with vCenterClient(vcenter_address, self.username, self.password).open() as vcenter_client:
            self._send('DrLogin.xml', username=self.username, key=vcenter_client.key)
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

    def get_remote_site(self):
        from munch import munchify
        with self.property_collector() as key:
            response = self._send('RetrievePropertiesEx.xml', key=key,
                                  specSet=[dict(propSet=[dict(type="DrRemoteSite", all=True)],
                                                objectSet=[dict(obj=dict(type="DrServiceInstance", value="DrServiceInstance"), partialUpdates=False,
                                                                selectSet=[dict(type="DrServiceInstance", path="content.remoteSiteManager",
                                                                                selectSet=[dict(type="DrRemoteSiteManager", path="remoteSiteList", selectSet=[])])])])])

        item = munchify(response).RetrievePropertiesExResponse.returnval.objects
        return dict(key=item.obj['#text'])

    def get_arrays(self):
        from munch import munchify
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
            [name] = [value.val['#text'] for value in item.propSet if value.name == 'name']
            [array_info] = [value.val for value in item.propSet if value.name == 'arrayInfo']
            [array_pair] = [value.val for value in item.propSet if value.name == 'arrayPair']
            pools = [] if 'DrStorageArrayInfo' not in array_info else \
                    [dict(id=array.key, name=array.name, peer_id=array.peerArrayId) for array in array_info.DrStorageArrayInfo] if isinstance(array_info.DrStorageArrayInfo, list) else\
                    [dict(id=array_info.DrStorageArrayInfokey, name=array_info.DrStorageArrayInfoname, peer_id=array_info.DrStorageArrayInfopeerArrayId)]
            pairs = [] if 'ManagedObjectReference' not in array_pair else \
                    [pair['#text'] for pair in array_pair.ManagedObjectReference] if isinstance(array_pair.ManagedObjectReference, list) else \
                    [array_pair.ManagedObjectReference['#text']]
            arrays.append(dict(key=item.obj['#text'], name=name, pools=pools, pairs=pairs))

        def _extract_pair(item):
            [info] = [value.val for value in item.propSet if value.name == 'info']
            [peer] = [value.val for value in item.propSet if value.name == 'peer']
            pairs.append(dict(key=item.obj['#text'], id=info.key, name=info.name, peer_id=peer.arrayId))

        for item in munchify(response).RetrievePropertiesExResponse.returnval.objects:
            if item.obj['#text'].startswith('storage-arraymanager'):
                _extract_array(item)
            elif item.obj['#text'].startswith('array-pair'):
                _extract_pair(item)

        for array in arrays:
            for pool in array['pools']:
                try:
                    [active_pair] = [pair for pair in pairs if pair['id'] == pool['id']]
                except ValueError:
                    pool.update(enabled=False)
                else:
                    pool.update(enabled=True, **active_pair)
        return arrays

    def refresh_array(self, array):
        self._send("DiscoverArrays_Task.xml", key=array['key'])

    def enable_array_pair(self, array, pool):
        remote_site = self.get_remote_site()
        self._send("AddArrayPair_Task.xml", key=array['key'], array_id=pool['id'], peer_array_id=pool['peer_id'], site_id=remote_site['key'])

    def disable_array_pair(self, array, pool):
        self._send("RemoveArrayPair_Task.xml", key=array['key'], pair_key=pool['key'])

