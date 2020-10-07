#!/usr/bin/env -u python

import subprocess
import sys
import requests
import datetime
import argparse
import logging

try:
    import docker
except ImportError as e:
    pass

LOGGER = logging.getLogger(__name__)

# TODO: Dockerize
# TODO: Write pytests


'''

CREATE TEST CONTAINERS:
docker run --name bla-haha1 -e VRE_USERNAME=franz -d alpine tail -f /dev/null
docker run --name bla-haha2 -e VRE_USERNAME=vre_blablabla -d alpine tail -f /dev/null
docker run --name bla-haha3 -d alpine tail -f /dev/null

USAGE:
python jupyter-container-deletion.py -p xxxx --url https://sdc-test.xxx.gr/getuserauthinfo -d 7 bla

Note: This uses python2 (raw_input, ...)

'''


PROGRAM_DESCRIP = '''This script deletes containers whose names
 start with specific prefixes and whose users have not
 logged in for a while.'''
VERSION = '20201007'

def find_all_existing_containers_plainpython():
    '''
    Returns a list of container names as strings.
    '''

    # Get docker ps -a output
    cmd = ['docker', 'ps', '-a']
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output, error = process.communicate()
    output_splitted = output.split('\n')
    # Each string is a line of the "docker ps -a" command output:
    #
    #'CONTAINER ID   IMAGE      COMMAND                CREATED          STATUS          PORTS   NAMES'
    #'663ad58662fe   alpine     "tail -f /dev/null"    16 minutes ago   Up 16 minutes           bla-kikiki'
    #
    # The first line is the header line. Words are separated by irregular numbers of spaces
    # (aligned for visual display), which makes empty cells hard to identify.

    # Extract just the names:
    all_container_names = []
    for line in output_splitted:

        if line.startswith('CONTAINER'):
            continue

        line = line.strip()

        if len(line) == 0:
            continue

        line = line.split()
        name = line[len(line)-1]
        name = name.lstrip('/')
        all_container_names.append(name)

    return all_container_names

def find_all_existing_containers(docker_client):
    '''
    Returns a list of container names.
    [u'/jupyter-franz', u'/jupyter-ina', u'/jupyter-ola', ...]
    '''
    all_container_names = []

    if docker_client is None:
        LOGGER.debug('No docker client. Using plain python.')
        return find_all_existing_containers_plainpython()

    for container in docker_client.containers(all=True):
        names = container['Names']
        if not len(names) == 1:
            LOGGER.warning('This container has several names: %s. Using the first one.' % names)
        name = names[0].lstrip('/')
        all_container_names.append(name)

    return all_container_names

def filter_container_names(all_container_names, startswith, yes):
    '''
    Collecting all names of containers to stop
    and delete:
    '''
    which_to_delete = []

    for name in all_container_names:

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
                LOGGER.info("You entered %s. Will not delete this one: %s" % (var, name))

    return which_to_delete

def delete_them_plainpython(which_to_delete):
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

def delete_them(which_to_delete, docker_client):
    '''
    Stopping and deleting.
    This takes some time.
    '''

    if docker_client is None:
        return delete_them_plainpython(which_to_delete)

    n = len(which_to_delete)

    if n == 0:
        LOGGER.info('No containers to be stopped. Bye!')
        sys.exit()

    LOGGER.info('Stopping and removing %s containers. This will take some seconds...' % n)

    for i in xrange(n):
        name = which_to_delete[i]
        LOGGER.debug('%s/%s: Stopping and removing "%s"...' % (i+1, n, name))
        docker_client.stop(name)
        docker_client.remove_container(name)

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
    try:
        username = env_dict['VRE_USERNAME']
        # TODO Do all containers have this?
        # At least my jupyters do!
        return username
    except KeyError as e:
        LOGGER.debug('Container env: %s' % env_dict)
        LOGGER.error('KeyError: %s' % e)
        LOGGER.warning("Cannot verify user's last login if no username is found. Bye!")
        sys.exit(1)
    
def check_when_last_logged_in(username, user_login_info):
    try:
        last_login = user_login_info[username] # 2020-09-03T08:41:22.000000Z
        last_login = last_login[:16] # 2020-09-03T08:41
        last_login = datetime.datetime.strptime(last_login, '%Y-%m-%dT%M:%S')
        return last_login
    except KeyError as e:
        LOGGER.debug('User login info for "%s": %s' % (username, user_login_info))
        LOGGER.error('KeyError: %s' % e)
        LOGGER.warning("Cannot verify user's last login if API returns no info on that. Bye!")
        sys.exit(1)

def request_login_times(api_url, secret):
    try:
        resp = requests.post(api_url, data=dict(secret=secret))

    except RequestException as e:
        LOGGER.error('Error while querying login times: %s' % e)
        LOGGEr.info('Bye!')
        sys.exit(1)

    if resp.status_code == 404:
        LOGGER.error('Error while querying login times: Received 404. Wrong URL?')
        LOGGEr.info('Bye!')
        sys.exit(1)
    elif 'Login with Marine ID' in resp.content:
        LOGGER.error('Error while querying login times: Not logged in. Wrong password?')

    # Convert to JSON
    try:
        user_login_info = resp.json()
    except json.decoder.JSONDecodeError as e:
        LOGGER.error('Error while querying login times: Could not read JSON response (%s)' % e)
        LOGGEr.info('Bye!')
        sys.exit(1)

    return user_login_info

def check_if_old_enough(candidates_to_delete, api_url, secret, docker_client, days):
    if days is None or days == 0:
        LOGGER.debug('Not checking for last login.')
        return candidates_to_delete

    which_to_delete = []

    # Request user login times from API (this may exit)
    user_login_info = request_login_times(api_url, secret)

    # Get username and matching login time:
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
            tmp += ', (%s (%s)' % item
        LOGGER.info('Will not delete: %s (%s days) ')

    return which_to_delete

def are_days_given(myargs):

    # Via command line:
    if 'days' in myargs:

        if myargs.days == 0:
            LOGGER.debug('Not checking for last login, as you '+
                'specified "--days 0".')
            return None

        else:
            return myargs.days

    # If user said --yes, they don't want to be asked, so if they did
    # not specify --days, then I guess they don't want!
    elif myargs.yes:
        return None

    # Ask user:
    else:
        question = 'Should we only delete containers of users'+ \
            ' that have not logged in since some days? How many'+ \
            ' days? Type a number, type "0" or "n" for no.'
        reply = raw_input(question)
        if reply == 'n' or reply == '0':
            LOGGER.debug('Not checking for last login, as you typed "%s".'
                % reply)
            return None
        else:
            try:
                days = int(reply)
            except ValueError as e:
                LOGGER.error('Could not understand the value you typed: %s (%s)' % (reply, e))
                LOGGER.info('Bye!')
                sys.exit(1)
            return days

def exit_if_cannot_login(myargs, doclient):

    # No URL and password for login check:
    if myargs.url is None:
        LOGGER.warn('Cannot check for last login without a URL! Bye!')
        sys.exit(1)
    if myargs.password is None:
        LOGGER.warn('Cannot check for last login without a password! Bye!')
        sys.exit(1)

    # No Docker client
    if doclient is None:
        LOGGER.warn('Cannot check for last login, as we have '+
                'no docker API library. Bye!')
        sys.exit(1)

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
    parser.add_argument("-d", "--days", type=int, action="store",
        help="Delete after how many days since user's last login? ")
    parser.add_argument("-y", "--yes", action="store_true",
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
    try:
        doclient = docker.APIClient()
    except NameError:

        if myargs.days and myargs.days > 0:
            LOGGER.warning('Cannot check for last login, as we have '+
                'no docker API library! (You can run this without '+
                'specifying --days"!). Bye.')
            sys.exit()
        else:
            LOGGER.warning('No docker library found. Will use plain python.')
            doclient = None # works with plain python then

    # Find all container names
    all_container_names = find_all_existing_containers(doclient)
    if len(all_container_names) == 0:
        LOGGER.info('No containers found. Exiting.')
        sys.exit()

    # Find container names starting with <prefix>
    which_to_delete = filter_container_names(all_container_names, myargs.prefix, myargs.yes)
    if len(which_to_delete) == 0:
        LOGGER.info('No containers found starting with %s. Exiting.' % myargs.prefix)
        sys.exit()

    # Does user want us to check login times?
    days = are_days_given(myargs)

    # Exit if we lack info for checking login times:
    if days is not None:
        exit_if_cannot_login(myargs, doclient)

    # Check for each container whether they are old enough
    if days is not None:
        which_to_delete = check_if_old_enough(which_to_delete,
            myargs.url, myargs.password, doclient, days)

    # Print all that will be deleted:
    LOGGER.debug('We will stop and delete all these:')
    for name in which_to_delete:
        LOGGER.debug(' * %s' % name)

    # Re-asking for permission to stop and delete them all
    if not myargs.yes:
        var = raw_input("Proceed with deletion? Type 'y'")
        if not var == 'y':
            LOGGER.info('Not stopping or deleting anything. Bye!')
            sys.exit()

    delete_them(which_to_delete, doclient)

    LOGGER.info('Done! Bye!')

