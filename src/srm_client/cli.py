"""SRM Client v{version}

Usage:
    srm list-plans    <hostname> <username> <password> [--debug]
    srm test          <plan-name> <hostname> <username> <password> [--debug]
    srm cleanupTest   <plan-name> <hostname> <username> <password> [--debug]
    srm failover      <plan-name> <hostname> <username> <password> [--debug]
    srm reprotect     <plan-name> <hostname> <username> <password> [--debug]
    srm revert        <plan-name> <hostname> <username> <password> [--debug]
    srm cancel        <plan-name> <hostname> <username> <password> [--debug]
    srm show-result   <plan-name> <hostname> <username> <password> [--debug]

Options:
    -h --help         show this screen.
    -v --version      show version.
    --debug           enable debug-level logging.

More information:
    srm list-plans    list all recovery plans and their status
    srm test          run a test failover to the peer (recovery) site, without halting the local (protected) site
    srm cleanupTest   after testing a recovery plan, cleans up all effects of the test operation
    srm failover      move to the peer (recovery) site; when all groups are moved the recovery plan is complete
    srm reprotect     the peer site becomes the protected site, and the local site becomes the recovery site
    srm cancel        reverse a failover, powering on virtual machines at the local site and abandoning the peer site
    srm show-result   get information about the last results of a recovery plan
"""

import colorama
import sys
import docopt
from infi.traceback import pretty_traceback_and_exit_decorator
from client import SrmClient, SrmClientException
from infi.pyutils.contexts import contextmanager
from tabulate import tabulate
import re
import logging

logger = logging.getLogger(__name__)


MODES = ('test', 'cleanupTest', 'failover', 'reprotect', 'revert')


@contextmanager
def _open(arguments):
    """ Open an SrmClient based on the connection information in the arguments """
    args = [arguments['<hostname>'], arguments['<username>'], arguments['<password>']]
    with SrmClient(*args).open() as client:
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
            if arguments['list-plans']:
                do_list_plans(arguments)
            elif any([arguments[mode] for mode in MODES]):
                do_start(arguments)
            elif arguments['cancel']:
                do_cancel(arguments)
            elif arguments['show-result']:
                do_show_result(arguments)
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
    return _main(arguments)
