"""SRM Client v{version}

Usage:
    srm list-plans <hostname> <username> <password> [--debug]
    srm start (test|cleanupTest|failover|reprotect|revert) <plan-name> <hostname> <username> <password> [--debug]
    srm cancel <plan-name> <hostname> <username> <password> [--debug]

Options:
    -h --help                             show this screen.
    -v --version                          show version.
    --debug                               enable debug-level logging.

More information:
    srm list-plans                        list all recovery plans and their status
"""

import colorama
import sys
import docopt
from infi.traceback import pretty_traceback_and_exit_decorator
from client import SrmClient, SrmClientException
from infi.pyutils.contexts import contextmanager
import logging

logger = logging.getLogger(__name__)


MODES = ('test', 'cleanupTest', 'failover', 'reprotect', 'revert')


@contextmanager
def _open(arguments):
    args = [arguments['<hostname>'], arguments['<username>'], arguments['<password>']]
    with SrmClient(*args).open() as client:
        yield client


def _plan_name_to_moref(client, name):
    plans = client.get_recovery_plans()
    if name not in client.get_recovery_plans():
        raise SrmClientException('Recovery plan called "%s" not found' % name)
    return plans[name]['moref']


def do_list_plans(arguments):
    from tabulate import tabulate
    with _open(arguments) as client:
        plans = client.get_recovery_plans()
        table = [[key, plan['state'], len(plan['groups'])] for key, plan in plans.iteritems()]
        print tabulate(table, ['NAME', 'STATE', 'PROTECTION GROUPS'], tablefmt='rst')


def do_start(arguments):
    with _open(arguments) as client:
        for mode in MODES:
            if arguments[mode]:
                break
        name = arguments['<plan-name>']
        client.recovery_start(_plan_name_to_moref(client, name), mode)


def do_cancel(arguments):
    with _open(arguments) as client:
        name = arguments['<plan-name>']
        client.recovery_cancel(_plan_name_to_moref(client, name))


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
            elif arguments['start']:
                do_start(arguments)
            elif arguments['cancel']:
                do_cancel(arguments)
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
