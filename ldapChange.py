#!/usr/bin/python
#
# This script will parse the ldap change logs.  It will need to 
# keep track of the logs already processed by change ID.  It will 
# then need to send a cef message into syslog.

# Imports
import re

# Globals
logDir = '/Users/eparker/scripts/git/ldap-logs'
logFile = logDir + '/auditlog.ldif'
logDb = logDir + '/change.db'

start_reg = re.compile(r'# modify\s+(\d+).*')

def parsefile(oldIds):
    print oldIds
    
    for line in open(logFile):
        line = line.strip()
        
        start_match = re.search(start_reg,line)
        if start_match:
            change_id = start_match.group(1)
            print change_id

def main():
    prevId = [] 
    # Create a tuple of all previous logs
    for line in open(logDb):
        line = line.strip()
        prevId.append(line)
    
    parsefile(prevId)

    
# Write out new id's    


if __name__ == '__main__':
    main()
