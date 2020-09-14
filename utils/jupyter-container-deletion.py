#!/usr/bin/env -u python

import subprocess
import sys

prefix = raw_input('Please enter container prefix (e.g. "jupyter"). Containers whose name start with this will be offered for deletion.')


#
# Finding all running/not running containers:
#
cmd = ['docker', 'ps', '-a']
process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
output, error = process.communicate()
print(output)
output = output.split('\n')


#
# Collecting all names of containers to stop
# and delete:
which_to_delete = []
STARTWITH = prefix or 'jupyter-'

for line in output:

    if line.startswith('CONTAINER'):
        continue

    line = line.strip()

    if len(line) == 0:
        continue

    line = line.split()
    name = line[len(line)-1]

    if not name.startswith(STARTWITH):
        print('Ignoring "%s"...' % name)
        continue

    var = raw_input("Delete '%s' ? Type 'y'" % name)
    if var == 'y':
        which_to_delete.append(name)
    else:
        print("You entered %s. Will not delete this one." % var)

#
# Re-asking for permission to stop and delete them all
#
print('Okay, thanks. We will stop and delete all these:')
for name in which_to_delete:
    print(' * %s' % name)

var = raw_input("Okay? Type 'y'")
if not var == 'y':
    print('Not stopping or deleting anything. Bye!')
    sys.exit()

#
# Stopping and deleting.
# This takes some time.
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

print('Done!')

