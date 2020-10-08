#!/usr/bin/env -u python
# python 3!

import sys
import requests
import datetime
import time
import logging
import docker
import os

LOGGER = logging.getLogger(__name__)

# TODO: Dockerize
# TODO: Write pytests


'''

CREATE TEST CONTAINERS:
docker run --name bla-haha1 -e VRE_USERNAME=franz -d alpine tail -f /dev/null
docker run --name bla-haha2 -e VRE_USERNAME=vre_xxx -d alpine tail -f /dev/null
docker run --name bla-haha3 -d alpine tail -f /dev/null

USAGE:
API_PASSWORD='xxx'
API_URL='https://sdc-test.xxx.gr/getuserauthinfo'
NUM_DAYS_SINCE_LAST_LOGIN=7
PREFIX='bla'
python jupyter-container-deletion-not-interactive.py

'''


PROGRAM_DESCRIP = '''This script deletes containers whose names
 start with specific prefixes and whose users have not
 logged in for a while.'''
VERSION = '20201008'
EXIT_FAIL = 1

def find_all_existing_containers(docker_client):
    '''
    Returns a list of container names.
    [u'/jupyter-franz', u'/jupyter-ina', u'/jupyter-ola', ...]
    '''
    all_container_names = []

    for container in docker_client.containers(all=True):
        names = container['Names']
        if not len(names) == 1:
            LOGGER.warning('This container has several names: %s. Using the first one.' % names)
        name = names[0].lstrip('/')
        all_container_names.append(name)

    return all_container_names

def filter_container_names(all_container_names, startswith):
    '''
    Collecting all names of containers to stop
    and delete:
    '''
    which_to_delete = []

    for name in all_container_names:

        if not name.startswith(startswith):
            LOGGER.debug('Ignoring "%s"...' % name)
        else:
            which_to_delete.append(name)

    return which_to_delete

def delete_them(which_to_delete, docker_client):
    '''
    Stopping and deleting.
    This takes some time.
    '''

    n = len(which_to_delete)

    if n == 0:
        LOGGER.info('No containers to be stopped.')
        return True

    LOGGER.info('Stopping and removing %s containers. This will take some seconds...' % n)

    for i in xrange(n):
        name = which_to_delete[i]
        LOGGER.debug('%s/%s: Stopping and removing "%s"...' % (i+1, n, name))
        docker_client.stop(name)
        docker_client.remove_container(name)

    LOGGER.debug('Finished deleting!')
    return True

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
        LOGGER.error('KeyError: %s in env of "%s"' % (e, containername))
        LOGGER.warning("Cannot verify user's last login if no username is found.")
        return None
    
def check_when_last_logged_in(username, user_login_info):
    try:
        last_login = user_login_info[username] # 2020-09-03T08:41:22.000000Z
        last_login = last_login[:16] # 2020-09-03T08:41
        last_login = datetime.datetime.strptime(last_login, '%Y-%m-%dT%M:%S')
        return last_login
    except KeyError as e:
        LOGGER.debug('User login info for all users: %s' % (user_login_info))
        LOGGER.error('KeyError: %s (not contained in user login info).' % e)
        LOGGER.warning("Cannot verify user's last login for '%s' if API returns no info on that." % username)
        return None

def request_login_times(api_url, secret):
    '''
    Request the login times for all users from the dashboard API
    and returns them as JSON.

    May raise ValueError.
    '''
    try:
        resp = requests.post(api_url, data=dict(secret=secret))

    except RequestException as e:
        err = 'Error while querying login times: %s' % e
        LOGGER.error(err)
        raise ValueError(err)

    if resp.status_code == 404:
        err = 'Error while querying login times: Received 404. Wrong URL?'
        LOGGER.error(err)
        raise ValueError(err)

    elif 'Login with Marine ID' in resp.content:
        err = 'Error while querying login times: Not logged in. Wrong password?'
        LOGGER.error(err)
        raise ValueError(err)        

    # Convert to JSON
    try:
        user_login_info = resp.json()
    except json.decoder.JSONDecodeError as e:
        err = 'Error while querying login times: Could not read JSON response (%s)' % e
        LOGGER.error(err)
        raise ValueError(err)        

    return user_login_info

def check_if_old_enough(candidates_to_delete, api_url, secret, docker_client, days):
    '''
    May raise ValueError.
    '''

    if days is None or days == 0:
        LOGGER.debug('Not checking for last login.')
        return candidates_to_delete

    which_to_delete = []

    # Request user login times from API (this may raise ValueError)
    user_login_info = request_login_times(api_url, secret)

    # Get username and matching login time:
    wont_delete = []
    for candidate in candidates_to_delete:

        username = get_username_for_container(candidate, docker_client)
        if username is None:
            wont_delete.append((candidate, 'username unknown'))
            continue

        last_login = check_when_last_logged_in(username, user_login_info)
        if last_login is None:
            wont_delete.append((candidate, 'last login unknown'))
            continue

        diff = datetime.datetime.now() - last_login
        if diff.days > days:
            LOGGER.debug('%s: User has not logged in for %s days - deleting!' % (username, diff.days))
            which_to_delete.append(candidate)
        else:
            LOGGER.debug('%s: User has logged in %s days ago! Not deleting!' % (username, diff.days))
            wont_delete.append((candidate, '%s days' % diff.days))

    # Log:
    if len(wont_delete) > 0:
        tmp = '%s (%s)' % wont_delete.pop()
        for item in wont_delete:
            tmp += ', (%s (%s)' % item
        LOGGER.info('Will not delete: %s' % tmp)

    return which_to_delete

def exit_if_cannot_login(url, password, doclient):

    # No URL and password for login check:
    if url is None:
        LOGGER.warn('Cannot check for last login without a URL! Bye!')
        sys.exit(EXIT_FAIL)

    if password is None:
        LOGGER.warn('Cannot check for last login without a password! Bye!')
        sys.exit(EXIT_FAIL)

    # No Docker client
    if doclient is None:
        LOGGER.warn('Cannot check for last login, as we have '+
                'no docker API library. Bye!')
        sys.exit(EXIT_FAIL)

def one_deletion_run(doclient, prefix, api_url, api_password, days):

    # Find all container names
    all_container_names = find_all_existing_containers(doclient)
    if len(all_container_names) == 0:
        LOGGER.info('No containers found at all.')
        LOGGER.info('No containers to be deleted.')
        return True

    # Find container names starting with <prefix>
    which_to_delete = filter_container_names(all_container_names, prefix)
    if len(which_to_delete) == 0:
        LOGGER.info('No containers found starting with %s.' % prefix)
        LOGGER.info('No containers to be deleted.')
        return True

    # Does user want us to check login times?
    if days == 0:
        LOGGER.debug('Not checking for last login, as you '+
            'specified "--days 0".')
        days = None

    # Exit if we lack info for checking login times:
    if days is not None:
        exit_if_cannot_login(api_url, api_password, doclient)

    # Check for each container whether they are old enough
    if days is not None:

        try:
            which_to_delete = check_if_old_enough(which_to_delete,
                api_url, api_password, doclient, days)
            if len(which_to_delete) == 0:
                LOGGER.info('No containers found that are older than %s days.' % days)
                LOGGER.info('No containers to be deleted.')
                return True

        except ValueError as e:
            LOGGER.warning('Could not check for login times. Stopping. This may be temporary, so try again.')
            return False

    # Print all that will be deleted:
    LOGGER.debug('We will stop and delete all these:')
    for name in which_to_delete:
        LOGGER.debug(' * %s' % name)

    success = delete_them(which_to_delete, doclient)
    return success

if __name__ == '__main__':

    # Get commandline args
    LOG_LEVEL = os.getenv('LOG_LEVEL')
    URL = os.getenv('API_URL')     # The URL to query to get info about login times.
    PW = os.getenv('API_PASSWORD') # The secret to query the API to get info about login times.
    EVERY = os.getenv('EVERY')     # Run continuously, until stopped, every x hours
    PREFIX = os.getenv('PREFIX')   # Container name should start with this.
    NUM_DAYS = os.getenv('NUM_DAYS_SINCE_LAST_LOGIN') # Delete after how many days since user's last login?

    # Configure logging
    root = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)5s - %(message)s') # with padding!
    handler.setFormatter(formatter)
    root.addHandler(handler)
    lvl = logging.getLevelName(LOG_LEVEL)
    try:
        root.setLevel(lvl)
    except ValueError as e:
        err = 'Could not understand log level "%s".' % lvl
        LOGGER.warn(err)
        sys.exit(EXIT_FAIL)

    # Check some args:
    if EVERY is not None:
        try:
            EVERY = int(EVERY)
        except ValueError as e:
            LOGGER.error('This value is not allowed for EVERY: %s. Bye!' % EVERY)
            sys.exit(EXIT_FAIL)

        if EVERY <= 0:
            LOGGER.error('This value is not allowed for EVERY: %s. Bye!' % EVERY)
            sys.exit(EXIT_FAIL)

    if NUM_DAYS is not None:
        try:
            NUM_DAYS = int(NUM_DAYS)
        except ValueError as e:
            LOGGER.error('This value is not allowed for NUM_DAYS: %s. Bye!' % EVERY)
            sys.exit(EXIT_FAIL)
   
    # Docker client
    doclient = docker.APIClient()

    # Run once:
    if EVERY is None:
        success = one_deletion_run(doclient, PREFIX, API_URL, API_PASSWORD, NUM_DAYS)

        if not success:
            LOGGER.warning('Stopping. Bye!')
            sys.exit(EXIT_FAIL)

    # Run many times:
    else:
        sleep_hours = EVERY
        sleep_seconds = 60*60*sleep_hours
        while True:
            success = one_deletion_run(doclient, PREFIX, API_URL, API_PASSWORD, NUM_DAYS)

            if not success:
                LOGGER.warning('Failed. Trying again (second time) in a minute...')
                time.sleep(60)
                LOGGER.warning('Trying again (second time)...')
                success = one_deletion_run(doclient, PREFIX, API_URL, API_PASSWORD, NUM_DAYS)

            if not success:
                LOGGER.warning('Failed. Trying again (third time) in five minutes...')
                time.sleep(5*60)
                LOGGER.warning('Trying again (third time)...')
                success = one_deletion_run(doclient, PREFIX, API_URL, API_PASSWORD, NUM_DAYS)

            if not success:
                LOGGER.warning('Stopping. Bye!')
                sys.exit(EXIT_FAIL)

            LOGGER.info('Sleeping for %s hours...' % sleep_hours)
            time.sleep(sleep_seconds)

    LOGGER.info('Done! Bye!')


