#!/usr/bin/env -u python

import subprocess
import sys

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


if __name__ == '__main__':

    prefix = raw_input('Please enter container prefix (e.g. "jupyter"). Containers whose name start with this will be offered for deletion.')
    output = find_all_running_containers()
    which_to_delete = find_container_names(output, prefix)

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

