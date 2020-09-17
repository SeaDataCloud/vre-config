#!/usr/bin/env -u python

import subprocess
import sys
import requests
import datetime
import docker
import argparse

SECRET = 'foobar'
URL = 'https://endpoint-for-user-login-info'

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
    print(output)
    return output.split('\n')

def find_container_names(output, startswith='jupyter-'):
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
            print('Ignoring "%s"...' % name)
            continue

        var = raw_input("Delete '%s' ? Type 'y'" % name)
        if var == 'y':
            which_to_delete.append(name)
        else:
            print("You entered %s. Will not delete this one." % var)

    return which_to_delete

def delete_them(which_to_delete):
    '''
    Stopping and deleting.
    This takes some time.
    '''

    n = len(which_to_delete)

    if n == 0:
        print('No containers to be stopped. Bye!')
        sys.exit()

    print('Stopping and removing %s containers. This will take some seconds...' % n)

    for i in xrange(n):
        name = which_to_delete[i]
        print('%s/%s: Stopping and removing "%s"...' % (i+1, n, name))
        p1 = subprocess.call(['docker', 'stop', name])
        p2 = subprocess.call(['docker', 'rm', name])

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

    for candidate in candidates_to_delete:
        username = get_username_for_container(candidate, docker_client)
        last_login = check_when_last_logged_in(username, user_login_info)
        diff = datetime.datetime.now() - last_login
        if diff.days > days:
            print('%s: User has not logged in for %s days - deleting!' % (username, diff.days))
            which_to_delete.append(candidate)
        else:
            print('%s: User has in %s days ago! Not deleting!' % (username, diff.days))

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
    myargs = parser.parse_args()

    # Docker client
    doclient = docker.APIClient()

    # Which names to delete
    prefix = raw_input('Please enter container prefix (e.g. "jupyter"). Containers whose name start with this will be offered for deletion.')
    output = find_all_running_containers()
    which_to_delete = find_container_names(output, prefix)

    # Check for each container whether they are old enough
    only_old = raw_input('Should we only delete containers of users that have not logged in since some days? How many days? Type a number, or "n" for no.')
    if only_old == 'n':
        pass
    else:
        days = int(only_old)
        which_to_delete = check_if_old_enough(candidates_to_delete,
            myargs.url, myargs.password, doclient, 7)

    # Re-asking for permission to stop and delete them all
    print('Okay, thanks. We will stop and delete all these:')
    for name in which_to_delete:
        print(' * %s' % name)

    var = raw_input("Okay? Type 'y'")
    if not var == 'y':
        print('Not stopping or deleting anything. Bye!')
        sys.exit()

    delete_them(which_to_delete)

    print('Done!')

