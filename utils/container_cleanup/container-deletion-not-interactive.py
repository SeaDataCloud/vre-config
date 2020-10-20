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

# TODO: Write pytests
# TODO: Add notification


'''

Usage from command line:
```
API_PASSWORD='xxx'
API_URL='https://sdc-test.xxx.gr/getuserauthinfo'
NUM_DAYS_SINCE_LAST_LOGIN=7
PREFIX='bla;bli'
PROTECTED_USERNAMES='kingkong;tarzan'
PROTECTED_CONTAINERS='bla-protected'
# Run:
python3 jupyter-container-deletion-not-interactive.py
```

Testing (using containerized version):

First, create test containers:

```
# These will not be deleted:
docker run --name bla-noinfo -e VRE_USERNAME=franz -d alpine tail -f /dev/null
docker run --name bla-nousername -d alpine tail -f /dev/null
docker run --name bla-protected -e VRE_USERNAME=fake-username-250days -d alpine tail -f /dev/null
docker run --name bla-protecteduser -e VRE_USERNAME=kingkong -d alpine tail -f /dev/null
docker run --name bla-loggedin-recently -e VRE_USERNAME=fake-username-10mins -d alpine tail -f /dev/null

# These will be deleted:
docker run --name bla-loggedin-longago -e VRE_USERNAME=fake-username-250days -d alpine tail -f /dev/null
docker run --name bli-other-prefix -e VRE_USERNAME=fake-username-250days -d alpine tail -f /dev/null

# Use a real name to test API:
docker run --name bla-loggedin-real -e VRE_USERNAME=vre_jcardosomarineidorgxyh81zia -d alpine tail -f /dev/null
```

Then run it:

```
docker run --name dele --mount type=bind,source="/var/run/docker.sock",target="/var/run/docker.sock" --env EVERY=2 --env PROTECTED_USERNAMES="kingkong" --env PROTECTED_CONTAINERS="bla-protected" --env PREFIX="bla;bli" --env NUM_DAYS=200 --env API_URL=https://vre.seadatanet.org/getuserauthinfo --env API_PASSWORD=xxx container_deletion:20201019
```

'''


PROGRAM_DESCRIP = '''This script deletes containers whose names
 start with specific prefixes and whose users have not
 logged in for a while.'''
VERSION = '20201019'
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

def filter_container_names(all_container_names, startswith_list):
    '''
    Collecting all names of containers to stop
    and delete:
    '''
    which_to_delete = []

    for name in all_container_names:
        was_matched = False
        for startswith in startswith_list:
            if name.startswith(startswith):
                was_matched = True
                continue

        if was_matched:
            which_to_delete.append(name)
        else:
            LOGGER.debug('Ignoring "%s"...' % name)

    return which_to_delete

def filter_protected(which_to_delete, protected_containers):
    new_which_to_delete = []
    for item in which_to_delete:
        if item in protected_containers:
            LOGGER.info('Will not delete "%s" (protected).' % item)
        else:
            new_which_to_delete.append(item)
    return new_which_to_delete

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

    for i in range(n):
        name = which_to_delete[i]
        LOGGER.info('%s/%s: Stopping and removing "%s"...' % (i+1, n, name))
        docker_client.stop(name)
        docker_client.remove_container(name)

    LOGGER.info('Finished stopping and removing!')
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
        err = 'Missing username: (variable %s) in env of container "%s".' % (e, containername)
        LOGGER.warning(err + " Cannot verify user's last login if no username is found.")
        return None
    
def check_when_last_logged_in(username, user_login_info):
    try:
        last_login = user_login_info[username] # 2020-09-03T08:41:22.000000Z
        last_login = last_login[:16] # 2020-09-03T08:41
        last_login = datetime.datetime.strptime(last_login, '%Y-%m-%dT%M:%S')
        return last_login
    except KeyError as e:

        # For testing:
        if username == 'fake-username-10mins':
            now = datetime.datetime.now()
            return now - datetime.timedelta(minutes=10)
        elif username == 'fake-username-250days':
            now = datetime.datetime.now()
            return now - datetime.timedelta(days=250)

        err = 'Missing user: "%s" (not contained in user login info).' % username
        LOGGER.warning(err + " Cannot verify user's last login if API returns no info for that user.")
        return None

def request_login_times(api_url, secret):
    '''
    Request the login times for all users from the dashboard API
    and returns them as JSON.

    May raise ValueError.
    '''
    try:
        resp = requests.post(api_url, data=dict(secret=secret))

    except requests.RequestException as e:
        err = 'Error while querying login times: %s' % e
        LOGGER.error(err)
        raise ValueError(err)

    if resp.status_code == 404:
        err = 'Error while querying login times: Received 404. Wrong URL?'
        LOGGER.error(err)
        raise ValueError(err)

    elif b'Login with Marine ID' in resp.content:
        err = 'Error while querying login times: Not logged in. Wrong password?'
        LOGGER.error(err)
        raise ValueError(err)        

    # Convert to JSON
    try:
        user_login_info = resp.json()
        LOGGER.debug('User login info for all users: %s' % (user_login_info))

    except json.decoder.JSONDecodeError as e:
        err = 'Error while querying login times: Could not read JSON response (%s)' % e
        LOGGER.error(err)
        raise ValueError(err)        

    return user_login_info

def check_if_name_protected(candidates_to_delete, docker_client, protected_usernames):
    wont_delete = []
    which_to_delete = []

    for candidate in candidates_to_delete:

        username = get_username_for_container(candidate, docker_client)
        
        if username is None:
            wont_delete.append((candidate, 'username unknown'))

        elif username in protected_usernames:
            wont_delete.append((candidate, 'username is protected'))

        else:
            which_to_delete.append(candidate)

    # Log:
    if len(wont_delete) > 0:
        tmp = '%s (%s)' % wont_delete.pop()
        for item in wont_delete:
            tmp += ', %s (%s)' % item
        LOGGER.info('Will not delete: %s' % tmp)

    return which_to_delete

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
            LOGGER.info('%s: User has not logged in for %s days - will delete: %s!' % (username, diff.days, candidate))
            which_to_delete.append(candidate)
        else:
            LOGGER.debug('%s: User has logged in %s days ago! Will not delete: %s!' % (username, diff.days, candidate))
            wont_delete.append((candidate, '%s days' % diff.days))

    # Log:
    if len(wont_delete) > 0:
        tmp = '%s (%s)' % wont_delete.pop()
        for item in wont_delete:
            tmp += ', %s (%s)' % item
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

def one_deletion_run(doclient, prefix_list, api_url, api_password, days,
                     protected_containers, protected_usernames):

    # Find all container names
    all_container_names = find_all_existing_containers(doclient)
    if len(all_container_names) == 0:
        LOGGER.info('No containers found at all.')
        LOGGER.info('No containers to be deleted.')
        return True

    # Find container names starting with <prefix>
    which_to_delete = filter_container_names(all_container_names, prefix_list)
    if len(which_to_delete) == 0:
        LOGGER.info('No containers found starting with %s.' % prefix_list)
        LOGGER.info('No containers to be deleted.')
        return True

    # Exclude the "protected" ones:
    which_to_delete = filter_protected(which_to_delete, protected_containers)

    # Exit if we lack info for checking login times:
    if days is not None:
        exit_if_cannot_login(api_url, api_password, doclient)

    # Check for each container whether the username is protected
    which_to_delete = check_if_name_protected(which_to_delete,
        doclient, protected_usernames)
    if len(which_to_delete) == 0:
        LOGGER.info('No containers found that not protected.')
        LOGGER.info('No containers to be deleted.')
        return True

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
            LOGGER.warning('Could not check for login times (this may be temporary), so could not delete anything.')
            return False

    # Print all that will be deleted:
    LOGGER.debug('Will stop and delete all these:')
    for name in which_to_delete:
        LOGGER.debug(' * %s' % name)

    success = delete_them(which_to_delete, doclient)
    return success

if __name__ == '__main__':

    # Get commandline args
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    API_URL = os.environ.get('API_URL', None)   # The URL to query to get info about login times.
    API_PASSWORD = os.environ.get('API_PASSWORD', None) # The secret to query the API to get info about login times.
    NO_CHECK = os.environ.get('NO_CHECK', None) # Explicitly tell not to check login time!
    EVERY = os.environ.get('EVERY', None)       # Run continuously, until stopped, every x hours
    PREFIX = os.environ.get('PREFIX', None)     # Container name should start with this.
    PROTECTED_CONTAINERS = os.environ.get('PROTECTED_CONTAINERS', None)
    PROTECTED_USERNAMES  = os.environ.get('PROTECTED_USERNAMES', None)
    NUM_DAYS = os.environ.get('NUM_DAYS', None) # Delete after how many days since user's last login?

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

    LOGGER.info('Running deletion tool, version %s' % VERSION)

    # Check some args:
    # Prefix
    if PREFIX is None:
        LOGGER.error('PREFIX must be set! Bye!')
        sys.exit(EXIT_FAIL)
    prefix_list = PREFIX.split(';')
    tmp = '", "'.join(prefix_list)
    LOGGER.info('Deletion of containers starting with "%s"' % tmp)

    # Protected continer names
    if PROTECTED_CONTAINERS is None:
        LOGGER.info('No protected containers.')
        PROTECTED_CONTAINERS = []
    else:
        PROTECTED_CONTAINERS = PROTECTED_CONTAINERS.split(';')

    # Protected usernames
    if PROTECTED_USERNAMES is None:
        LOGGER.info('No protected usernames.')
        PROTECTED_USERNAMES = []
    else:
        PROTECTED_USERNAMES = PROTECTED_USERNAMES.split(';')

    # Every how many hours
    if EVERY is None:
        LOGGER.error('PREFIX must be set! Bye!')
        sys.exit(EXIT_FAIL)

    try:
        EVERY = int(EVERY)
    except ValueError as e:
        LOGGER.error('This value is not allowed for EVERY: %s (%s). Bye!' % (EVERY, type(EVERY)))
        sys.exit(EXIT_FAIL)

    if EVERY <= 0:
        LOGGER.error('This value is not allowed for EVERY: %s. Bye!' % EVERY)
        sys.exit(EXIT_FAIL)

    now = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
    LOGGER.info('This script will run every %s hours (starting at %s).' % (EVERY, now))
    
    # If checking user login times is explicitly switched off:

    if NO_CHECK is not None and NO_CHECK.lower() == 'true':
        LOGGER.info('Will not check for last login time of the user, because NO_CHECK is set to: %s.' % NO_CHECK)
        NUM_DAYS = None

    else:

        # Num days must have a nonzero integer:

        if NUM_DAYS is None:
            LOGGER.error('NUM_DAYS must be set if NO_CHECK is not set! Bye!')
            sys.exit(EXIT_FAIL)
        
        try:
            NUM_DAYS = int(NUM_DAYS)
        except ValueError as e:
            LOGGER.error('This value is not allowed for NUM_DAYS: %s (%s). Bye!' % (NUM_DAYS, type(NUM_DAYS)))
            sys.exit(EXIT_FAIL)
    
        if NUM_DAYS <= 0:
            LOGGER.error('This value is not allowed for NUM_DAYS: %s. Bye!' % NUM_DAYS)
            sys.exit(EXIT_FAIL)

        LOGGER.info('Only container of users who logged in more than %s days ago will be deleted.' % NUM_DAYS)

        # We need also url and password:

        if API_URL is None:
            LOGGER.error('API_URL must be set if NUM_DAYS is set! Bye!')
            sys.exit(EXIT_FAIL)

        if API_PASSWORD is None:
            LOGGER.error('API_PASSWORD must be set if NUM_DAYS is set! Bye!')
            sys.exit(EXIT_FAIL)

    # Docker client
    # Needs mounted unix://var/run/docker.sock
    doclient = docker.APIClient()

    # Run many times:
    sleep_hours = EVERY
    sleep_seconds = 60*60*sleep_hours
    success = False
    while True:
        success = one_deletion_run(doclient, prefix_list, API_URL, API_PASSWORD,
                                   NUM_DAYS, PROTECTED_CONTAINERS, PROTECTED_USERNAMES)

        if success:
            
            with open('ishealthy.txt', 'w') as healthfile:
                now = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
                healthfile.write('OK: Worked at %s' % now)

        else:
            LOGGER.warning('Failed. Trying again (second time) in a minute...')
           
            with open('ishealthy.txt', 'w') as healthfile:
                now = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
                healthfile.write('FAILED: Failed first time at %s' % now)

            try:
                time.sleep(60)
            except KeyboardInterrupt:
                LOGGER.info('Stopped by user...')
                break

            # Second attempt
            LOGGER.warning('Trying again (second time)...')
            success = one_deletion_run(doclient, prefix_list, API_URL, API_PASSWORD, NUM_DAYS, PROTECTED_CONTAINERS, PROTECTED_USERNAMES)

        if not success:
            LOGGER.warning('Failed. Trying again (third time) in five minutes...')
            
            with open('ishealthy.txt', 'w') as healthfile:
                now = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
                healthfile.write('FAILED: Failed second time at %s' % now)

            try:
                time.sleep(5*60)
            except KeyboardInterrupt:
                LOGGER.info('Stopped by user...')
                break
            
            # Third attempt
            LOGGER.warning('Trying again (third time)...')
            success = one_deletion_run(doclient, prefix_list, API_URL, API_PASSWORD, NUM_DAYS, PROTECTED_CONTAINERS, PROTECTED_USERNAMES)

        if not success:
            with open('ishealthy.txt', 'w') as healthfile:
                now = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
                healthfile.write('FAILED: Failed third time at %s' % now)

            LOGGER.warning('Stopping. Bye!')
            sys.exit(EXIT_FAIL)

        LOGGER.info('Sleeping for %s hours...' % sleep_hours)
        try:
            time.sleep(sleep_seconds)
        except KeyboardInterrupt:
            LOGGER.info('Stopped by user...')
            break

    if not success:
        LOGGER.warning('Last try was not successful. Bye!')
        sys.exit(EXIT_FAIL)
    LOGGER.info('Done! Bye!')


