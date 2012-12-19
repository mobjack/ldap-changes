#!/usr/bin/python
#
# This script will parse the ldap change logs.  It will need to 
# keep track of the logs already processed by change ID.  It will 
# then need to send a cef message into syslog.

# Imports


# Globals
logDir = '/Users/eparker/scripts/git/ldap-logs'
logFile = logDir + '/auditlog.ldif'
logDb = logDir + '/change.db'


def main():
    prevId = [] 
    # Create a tuple of all previous logs
    for line in open(logDb):
        line = line.strip()
        prevId.append(line)

    print prevId
    
    


if __name__ == '__main__':
    main()
