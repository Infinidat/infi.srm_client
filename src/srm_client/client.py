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
        self.url = 'https://%s:8095/dr' % hostname
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

    def get_arrays(self):
        with self.property_collector() as key:
            self._send('CreateFilter.xml', key=key,
                       propSet=[dict(type="DrReplicationReplicationManager", value="replicationProvider"),
                                dict(type="DrReplicationHbrProvider", value="hbrOvfPath"),
                                dict(type="DrReplicationHbrProvider", value="hmsOvfPath"),
                                dict(type="DrReplicationHbrProvider", value="hmsServerInfo"),
                                dict(type="DrReplicationHbrProvider", value="remoteHmsServerInfo")],
                       objectSet=[dict(obj=dict(type="DrServiceInstance", value="DrServiceInstance"), partialUpdates=False,
                                       selectSet=[dict(type="DrServiceInstance", path="content.remoteSiteManager", skip=True, selectSet=[]),
                                                  dict(type="DrServiceInstance", path="content.replicationManager", skip=False, selectSet=[dict(type="DrReplicationReplicationManager",
                                                                                                                                                path="replicationProvider", skip=False)])])])
            self._send('CreateFilter.xml', key=key,
                       propSet=[dict(type="DrRemoteSite", value="connected"),
                                dict(type="DrRemoteSite", value="name"),
                                dict(type="DrServiceInstance", value="content.siteName")],
                       objectSet=[dict(obj=dict(type="DrServiceInstance", value="DrServiceInstance"), partialUpdates=False,
                                       selectSet=[dict(type="DrServiceInstance", path="content.remoteSiteManager", skip=True, selectSet=[]),
                                                  dict(type="DrRemoteSiteManager", path="remoteSiteList", skip=False, selectSet=[])])])
            self._send('CreateFilter.xml', key=key,
                       propSet=[dict(type="DrStorageStorageManager", value="arrayManager.length"),
                                dict(type="DrStorageArrayManager", value="name"),
                                dict(type="DrStorageArrayManager", value="arrayPair"),
                                dict(type="DrStorageArrayManager", value="arrayInfo"),
                                dict(type="DrStorageArrayManager", value="arrayDiscoveryStatus.fault"),
                                dict(type="DrStorageReplicatedArrayPair", value="owner"),
                                dict(type="DrStorageReplicatedArrayPair", value="deviceDiscoveryStatus.fault"),
                                dict(type="DrStorageReplicatedArrayPair", value="deviceDiscoveryStatus.peerMatchingFault"),
                                dict(type="DrStorageReplicatedArrayPair", value="deviceMatchingFault")],
                       objectSet=[dict(obj=dict(type="DrReplicationReplicationManager", value="DrReplicationManager"), partialUpdates=False,
                                       selectSet=[dict(type="DrReplicationReplicationManager", path="replicationProvider", skip=True, selectSet=[dict(type="DrReplicationStorageProvider", path="storageManager", skip=True, selectSet=[dict(type="DrStorageStorageManager", path="arrayManager", selectSet=[dict(type="DrStorageArrayManager", path="arrayPair", selectSet=[])])])])])])
            print self._send('WaitForUpdatesEx.xml', key=key, version='')
