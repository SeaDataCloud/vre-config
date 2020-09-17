#!/usr/bin/env -u python

import subprocess
import sys
import requests
import datetime
import docker
import argparse
import logging


LOGGER = logging.getLogger(__name__)


# TODO: All should be done using docker API

PROGRAM_DESCRIP = '''This script deletes containers whose names
 start with specific prefixes and whose users have not
 logged in for a while.'''
VERSION = '20200917'


def find_all_running_containers():
    # TODO use docker api
    cmd = ['docker', 'ps', '-a']
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output, error = process.communicate()
    return output.split('\n')

def find_container_names(output, startswith, yes):
    '''
    Collecting all names of containers to stop
    and delete:
    '''
    which_to_delete = []

    for line in output:

        if line.startswith('CONTAINER'):
            continue

        line = line.strip()

        if len(line) == 0:
            continue

        line = line.split()
        name = line[len(line)-1]

        if not name.startswith(startswith):
            LOGGER.debug('Ignoring "%s"...' % name)
            continue

        if yes:
            which_to_delete.append(name)
        else:
            var = raw_input("Delete '%s' ? Type 'y'" % name)
            if var == 'y':
                which_to_delete.append(name)
            else:
                LOGGER.info("You entered %s. Will not delete this one." % var)

    return which_to_delete

def delete_them(which_to_delete):
    '''
    Stopping and deleting.
    This takes some time.
    '''

    n = len(which_to_delete)

    if n == 0:
        LOGGER.info('No containers to be stopped. Bye!')
        sys.exit()

    LOGGER.info('Stopping and removing %s containers. This will take some seconds...' % n)

    for i in xrange(n):
        name = which_to_delete[i]
        LOGGER.debug('%s/%s: Stopping and removing "%s"...' % (i+1, n, name))
        p1 = subprocess.call(['docker', 'stop', name])
        p2 = subprocess.call(['docker', 'rm', name])

    LOGGER.debug('Finished deleting!')

def get_username_for_container(containername, docker_client):
    insp = docker_client.inspect_container(containername)
    docker_env = insp['Config']['Env']
    env_dict = {}
    for item in docker_env:
        kv = item.split('=')
        k = kv[0]
        v = kv[1]
        env_dict[k] = v
    return env_dict['VRE_USERNAME']
    # TODO Do all containers have this?
    # At least my jupyters do!

def check_when_last_logged_in(username, user_login_info):
    last_login = user_login_info[username] # 2020-09-03T08:41:22.000000Z
    last_login = last_login[:16] # 2020-09-03T08:41
    last_login = datetime.datetime.strptime(last_login, '%Y-%M-%DT%M:%S')
    return last_login

def check_if_old_enough(candidates_to_delete, api_url, secret, docker_client, days=7):
    which_to_delete = []
    user_login_info = requests.post(api_url, data=dict(secret=secret))
    user_login_info = user_login_info.json()

    wont_delete = []
    for candidate in candidates_to_delete:
        username = get_username_for_container(candidate, docker_client)
        last_login = check_when_last_logged_in(username, user_login_info)
        diff = datetime.datetime.now() - last_login
        if diff.days > days:
            LOGGER.debug('%s: User has not logged in for %s days - deleting!' % (username, diff.days))
            which_to_delete.append(candidate)
        else:
            LOGGER.debug('%s: User has logged in %s days ago! Not deleting!' % (username, diff.days))
            wont_delete.append((candidate, diff.days))

    # Log:
    if len(wont_delete) > 0:
        tmp = '%s (%s days)' % wont_delete.pop()
        for item in wont_delete:
            tmp += ', (%s (%s)' % item)
        LOGGER.info('Will not delete: %s (%s days) ')

    return which_to_delete


if __name__ == '__main__':

    # Get commandline args
    parser = argparse.ArgumentParser(description=PROGRAM_DESCRIP)
    parser.add_argument('--version', action='version',
        version='Version: %s' % VERSION)
    parser.add_argument('--verbose', '-v', action="store_true")
    parser.add_argument("-p","--password", action="store",
        help='The secret to query the API to get info about login times.')
    parser.add_argument("--url", action="store",
        help='The URL to query to get info about login times.')
    parser.add_argument("-y", "--yes", action="store",
        help="Do not ask for reconfirm (useful for scripting).")
    parser.add_argument('prefix', help='Container name should start with this.')
    myargs = parser.parse_args()

    # Configure logging
    root = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)5s - %(message)s') # with padding!
    handler.setFormatter(formatter)
    root.addHandler(handler )
    root.setLevel(logging.INFO)
    if myargs.verbose:
        root.setLevel(logging.DEBUG)
    
    # Docker client
    doclient = docker.APIClient()

    # Find all container names
    output = find_all_running_containers()
    if len(output) == 0:
        LOGGER.info('No containers found. Exiting.')
        sys.exit()

    # Find container names starting with <prefix>
    which_to_delete = find_container_names(output, myargs.prefix, myargs.yes)
    if len(which_to_delete) == 0:
        LOGGER.info('No containers found starting with %s. Exiting.' % myargs.prefix)
        sys.exit()

    # Check for each container whether they are old enough
    only_old = raw_input('Should we only delete containers of users that have not logged in since some days? How many days? Type a number, or "n" for no.')
    if only_old == 'n':
        pass
    else:
        days = int(only_old)
        which_to_delete = check_if_old_enough(candidates_to_delete,
            myargs.url, myargs.password, doclient, days)

    # Print all that will be deleted:
    LOGGER.debug('Okay, thanks. We will stop and delete all these:')
    for name in which_to_delete:
        LOGGER.debug(' * %s' % name)

    # Re-asking for permission to stop and delete them all
    if not myargs.yes:
        var = raw_input("Okay? Type 'y'")
        if not var == 'y':
            LOGGER.info('Not stopping or deleting anything. Bye!')
            sys.exit()

    delete_them(which_to_delete)

    LOGGER.debug('Done!')

