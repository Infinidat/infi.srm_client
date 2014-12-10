"""SRM Client v{version}

Usage:
    srm [options] plan list
    srm [options] plan test              <plan-name>
    srm [options] plan cleanupTest       <plan-name>
    srm [options] plan failover          <plan-name>
    srm [options] plan reprotect         <plan-name>
    srm [options] plan revert            <plan-name>
    srm [options] plan cancel            <plan-name>
    srm [options] plan show-result       <plan-name>
    srm [options] plan delete            <plan-name>
    srm [options] plan create            <plan-name> [<group-name>...]
    srm [options] device list            [--refresh]
    srm [options] adapter list
    srm [options] array delete           <array-name>
    srm [options] array create           <array-name> <array-type> [<parameter>...]
    srm [options] array-pair list        [--refresh]
    srm [options] array-pair enable      <array-pair-name>
    srm [options] array-pair disable     <array-pair-name>
    srm [options] group list
    srm [options] group delete           <group-name>
    srm [options] group create           <group-name> [<datastore-name>...]

Options:
    -h --help                   show this screen.
    -v --version                show version.
    --debug                     enable debug-level logging.
    --srm-server=<srv-server>   srm server addresss
    --srm-username=<username>       username
    --srm-password=<password>       password

More information:
    srm plan test                    run a test failover to the peer (recovery) site, without halting the local (protected) site
    srm plan cleanupTest             after testing a recovery plan, cleans up all effects of the test operation
    srm plan failover                move to the peer (recovery) site; when all groups are moved the recovery plan is complete
    srm plan reprotect               the peer site becomes the protected site, and the local site becomes the recovery site
    srm plan cancel                  reverse a failover, powering on virtual machines at the local site and abandoning the peer site
    srm plan show-result             get information about the last results of a recovery plan
"""

import colorama
import sys
import docopt
from infi.traceback import pretty_traceback_and_exit_decorator
from client import SrmClient, InternalSrmClient, SrmClientException
from infi.pyutils.contexts import contextmanager
from tabulate import tabulate
import re
import logging

logger = logging.getLogger(__name__)


MODES = ('test', 'cleanupTest', 'failover', 'reprotect', 'revert')


def _extract_server_args_from_arguments(arguments):
    from os import environ
    return (arguments['--srm-server'] if 'SRM_SERVER' not in environ else arguments.get('--srm-server') or environ['SRM_SERVER'],
            arguments['--srm-username'] if 'SRM_USERNAME' not in environ else arguments.get('--srm-username') or environ['SRM_USERNAME'],
            arguments['--srm-password'] if 'SRM_PASSWORD' not in environ else arguments.get('--srm-password') or environ['SRM_PASSWORD'],
            )


@contextmanager
def _open(arguments):
    """ Open an SrmClient based on the connection information in the arguments """
    from os import environ
    with SrmClient(*_extract_server_args_from_arguments(arguments)).open() as client:
        yield client


@contextmanager
def _internal_open(arguments):
    """ Open an SrmClient based on the connection information in the arguments """
    with InternalSrmClient(*_extract_server_args_from_arguments(arguments)).open() as client:
        yield client


def _plan_name_to_moref(client, name):
    """ Get the moref of a recovery plan by its name """
    plans = client.get_recovery_plans()
    if name not in client.get_recovery_plans():
        raise SrmClientException('Recovery plan called "%s" not found' % name)
    return plans[name]['moref']


def _decamelize(s):
    """ Split camelcase string to words in lowercase """
    return re.sub('(?!^)([A-Z]+)', r' \1', s).lower()


def do_list_plans(arguments):
    with _open(arguments) as client:
        plans = client.get_recovery_plans()
        table = [[key, plan['state'], len(plan['groups'])] for key, plan in plans.iteritems()]
        print tabulate(table, ['NAME', 'STATE', 'PROTECTION GROUPS'], tablefmt='rst')


def do_list_arrays(arguments):
    with _internal_open(arguments) as client:
        if arguments['--refresh']:
            for array in client.get_arrays():
                client.refresh_array(array)

        arrays = client.get_arrays()
        table = []
        for array in arrays:
            if not array['pools']:
                print 'no arrays detected for %s' % array['name']
            for pool in array['pools']:
                table.append([pool['name'], pool['id'], pool['peer_id'], 'YES' if pool['enabled'] else 'NO'])
        print ''
        print tabulate(table, ['NAME', 'ID', 'PEER ID', 'ENABLED'], tablefmt='rst')


def do_list_devices(arguments):
    with _internal_open(arguments) as client:
        if arguments['--refresh']:
            for array in client.get_arrays():
                client.refresh_array(array)

        arrays = client.get_arrays()
        table = []
        for array in arrays:
            if not array['pools']:
                print 'no arrays detected for %s' % array['name']
            for pool in array['pools']:
                for device in pool['devices']:
                    table.append([device['name'], device['role'], 'YES' if 'key' in device else 'NO'])
        print ''
        print tabulate(table, ['NAME', 'ROLE', 'HAS LOCAL DATASTORE'], tablefmt='rst')


def do_list_adapters(arguments):
    with _internal_open(arguments) as client:
        adapters = client.get_adapters()
        table = []
        for adapter in adapters:
            table.append([adapter['name'], adapter['version'], adapter['connection_parameters']])
        print tabulate(table, ['NAME', 'VERSION', 'CONNECTION PARAMETERS'], tablefmt='rst')


def do_list_protection_groups(arguments):
    with _internal_open(arguments) as client:
        table = []
        for group in client.get_protection_groups():
            table.append([group['name'], group['state'],
                          ' '.join([item['name'] for item in group['protected_datastores']]),
                          len(group['protected_vms'])])
        print tabulate(table, ['NAME', 'STATE', 'DATASTORES', 'VIRTUAL MACHINES'], tablefmt='rst')


def do_enable_pair(arguments):
    with _internal_open(arguments) as client:
        _tuple = None
        for array in client.get_arrays():
            for pool in array['pools']:
                if pool['name'] == arguments['<array-pair-name>']:
                    _tuple = array, pool
        assert _tuple is not None
        client.enable_array_pair(*_tuple)


def do_disable_pair(arguments):
    with _internal_open(arguments) as client:
        _tuple = None
        for array in client.get_arrays():
            for pool in array['pools']:
                if pool['name'] == arguments['<array-pair-name>']:
                    _tuple = array, pool
        assert _tuple is not None
        client.disable_array_pair(*_tuple)


def do_delete_protection_group(arguments):
    with _internal_open(arguments) as client:
        [group] = [item for item in client.get_protection_groups() if item['name'] == arguments['<group-name>']]
        client.delete_protection_group(group)


def do_create_protection_group(arguments):
    with _internal_open(arguments) as client:
        datastore_names = arguments['<datastore-name>']
        datastores = [item for item in client.get_unprotected_datastores() if item['name'] in datastore_names]
        assert len(datastore_names) == len(datastores)
        assert len({item['pair'] for item in datastores}) == 1
        client.create_protection_group(arguments['<group-name>'], datastores)


def do_delete_recovery_plan(arguments):
    with _internal_open(arguments) as internal_client, _open(arguments) as client:
        internal_client.delete_recovery_plan(client.get_recovery_plans()[arguments['<plan-name>']])


def do_create_recovery_plan(arguments):
    with _internal_open(arguments) as client:
        protection_groups = [item for item in client.get_protection_groups() if
                             item['name'] in arguments['<group-name>']]
        client.create_recovery_plan(arguments['<plan-name>'], protection_groups)


def do_create_array(arguments):
    with _internal_open(arguments) as client:
        [adapter] = [item for item in client.get_adapters() if
                     item['name'] == arguments['<array-type>']]
        connection_parameters = [dict(key=value, value=arguments['<parameter>'][index]) for
                                      index, value in enumerate(adapter['connection_parameters'])]
        client.create_adapter(adapter, arguments['<array-name>'], connection_parameters)


def do_delete_array(arguments):
    with _internal_open(arguments) as client:
        [adapter] = [item for item in client.get_arrays() if
                     item['name'] == arguments['<array-name>']]
        client.delete_adapter(adapter)


def do_start(arguments):
    with _open(arguments) as client:
        for mode in MODES:
            if arguments[mode]:
                name = arguments['<plan-name>']
                client.recovery_start(_plan_name_to_moref(client, name), mode)
                break


def do_cancel(arguments):
    with _open(arguments) as client:
        name = arguments['<plan-name>']
        client.recovery_cancel(_plan_name_to_moref(client, name))


def do_show_result(arguments):
    with _open(arguments) as client:
        name = arguments['<plan-name>']
        result = client.get_recovery_result(_plan_name_to_moref(client, name))
        table = [(_decamelize(key), value) for key, value in result.iteritems()]
        print tabulate(table, tablefmt='rst')


def parse_commandline_arguments(argv):
    from srm_client.__version__ import __version__
    return docopt.docopt(__doc__, argv=argv, version=__version__)


def srm(argv=sys.argv[1:]):
    @pretty_traceback_and_exit_decorator
    def _main(arguments):
        try:
            if arguments['--debug']:
                logging.basicConfig(level=logging.DEBUG)
            if arguments['plan']:
                if arguments['list']:
                    do_list_plans(arguments)
                elif any([arguments[mode] for mode in MODES]):
                    do_start(arguments)
                elif arguments['create']:
                    do_create_recovery_plan(arguments)
                elif arguments['delete']:
                    do_delete_recovery_plan(arguments)
                elif arguments['cancel']:
                    do_cancel(arguments)
                elif arguments['show-result']:
                    do_show_result(arguments)
            elif arguments['device']:
                do_list_devices(arguments)
            elif arguments['adapter']:
                do_list_adapters(arguments)
            elif arguments['array']:
                if arguments['create']:
                    do_create_array(arguments)
                elif arguments['delete']:
                    do_delete_array(arguments)
            elif arguments['array-pair']:
                if arguments['list']:
                        do_list_arrays(arguments)
                elif arguments['enable']:
                    do_enable_pair(arguments)
                elif arguments['disable']:
                    do_disable_pair(arguments)
            elif arguments['group']:
                if arguments['list']:
                    do_list_protection_groups(arguments)
                elif arguments['create']:
                    do_create_protection_group(arguments)
                elif arguments['delete']:
                    do_delete_protection_group(arguments)
        except SrmClientException, e:
            sys.stderr.write("ERROR: %s\n" % e.message)
            return 1
        except SystemExit:
            return 1
        except KeyboardInterrupt:
            return 1
        except:
            logger.exception("Unhandled exception")
            raise
    # we want to parse the command-line arguments, and once we succeed we want to have the pretty traceback
    arguments = parse_commandline_arguments(argv)
    colorama.init()

    # Prevent urllib3 from warning about certificates
    from requests.packages import urllib3
    urllib3.disable_warnings()
    return _main(arguments)
