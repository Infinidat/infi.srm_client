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
