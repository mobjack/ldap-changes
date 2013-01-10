#!/usr/bin/python
#
# This script will parse the ldap change logs.  It will need to 
# keep track of the logs already processed by change ID.  It will 
# then need to send a cef message into syslog.

# Imports
from collections import defaultdict
import re
import sys
import os
import calendar
import syslog

# Globals
cef_vend = 'mozilla'
cef_prod = 'Openldap Change Script'
cef_vers = '0.1'
cef_id = '4'
cef_sev = '4'


#logDir = '/home/eric/scripts/git/ldap-logs'
logDir = '/Users/eparker/scripts/git/ldap-logs'
logFile = logDir + '/auditlog.ldif'
logDb = logDir + '/change.db'

start_reg = re.compile(r'# modify\s+(\d+).*')
dn_reg = re.compile(r'-->dn: mail=(.*?)\,.*')
id_reg = re.compile(r'--># modify (\d+)\s+(.*?)\s+-->')
change_reg = re.compile(r'-->changetype:\s+(\w+)\s+-->replace:\s+(\w+)')
date_reg = re.compile(r'(\d\d\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)')

def logit(cef):
    syslog.openlog('ldapChanges', 0, syslog.LOG_LOCAL4)
    syslog.syslog(syslog.LOG_INFO, cef)
    syslog.closelog

def cefit(cefblob):
    log_ext = ''
    #print cefblob.items()
    print ''
    # Standard CEF
    #CEF header:
    #CEF:0|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|
    
    if cefblob['name']:
        cef_head =  'CEF:0|' + cef_vend + '|' + cef_prod + '|' + cef_vers + '|' + cef_id + '|' + cefblob['name'] + '|' + cef_sev + '|'
    else:
        print 'Exit: no name given'
        print cefblob.items()
        os.sys.exit()
    
    #Extenstions
    for log_key in cefblob.keys():
        if log_key == 'name':
            continue # Skip it this is in the header
        
        log_ext = log_key + '=' + cefblob[log_key] + ' ' + log_ext
        
    #Pull em together for full CEF message, muha ha ha!
    cef_msg = cef_head + log_ext
    print cef_msg

def datecef(ldapdate):
    date_find = re.search(date_reg,ldapdate)
    if date_find:
        lyear = date_find.group(1)
        lmon = int(date_find.group(2))
        mon_low = calendar.month_abbr[lmon]
        mon_name = mon_low.upper()
        
        lday = date_find.group(3)
        lhour = date_find.group(4)
        lmin = date_find.group(5)
        lsec = date_find.group(6)
    
    cef_stamp = mon_name + ' ' + lday + ' ' + lyear + ' ' + lhour + ':' + lmin + ':' + lsec 
    return cef_stamp    
    
def eqclean(eqblob):
    return eqblob.replace('=','\=')
    
def spank(blob):
    lcef = {}
    #print blob
    
    # find the id
    id_find = re.search(id_reg,blob)
    if id_find:
        lcef['cn1'] = id_find.group(1)
        lcef['cn1Label'] = 'logId'
        lcef['cs4'] = eqclean(id_find.group(2))
        lcef['cs4Label'] = 'fullDN'
        
    
    # find the dn
    user_find = re.search(dn_reg,blob)
    if user_find:
        lcef['suser'] = user_find.group(1)
        
    # find the change and modify name
    change_find = re.search(change_reg,blob)
    if change_find:
        change_type = change_find.group(1)
        mod_param = change_find.group(2)
        lcef['cs2'] = change_type
        lcef['cs2Label'] = 'changeType'
        
        lcef['cs3'] = mod_param
        lcef['cs3Label'] = 'modParameter'
        
        lcef['name'] = change_type + " " + mod_param
        
    mod_find = re.search(r'-->'+str(mod_param)+r':\s+(\d+)',blob)
    if mod_find and mod_param == 'hgAccessDate':
        change_date = datecef(mod_find.group(1))
        lcef['end'] = change_date

    #print lcef.items()
    cefit(lcef)

def parsefile(oldIds):
    #print oldIds
    mid_track = 'off'
    log_minder = ''
    # Set up the main data structure, values will default to a new string.
    connections = defaultdict(str)
    
    
    for line in open(logFile):
        line = line.strip()
        
        # Start of a new change log
        start_match = re.search(start_reg,line)
        if start_match:
            change_id = start_match.group(1)
            mid_track = 'on'    

        if mid_track == 'on': # start collecting data within
            if line == '-':
                continue
            log_minder = log_minder + " -->" + line
            
            
        end_modify = '# end modify ' + change_id
        end_add = '# end add ' + change_id
        if line == end_modify or line == end_add:
            # done with that log entry now parse it
            spank(log_minder)
            mid_track = 'off'
            del log_minder
            sys.exit()   

def main():
    prevId = [] 
    # Create a tuple of all previous logs
    for line in open(logDb):
        line = line.strip()
        prevId.append(line)
    
    parsefile(prevId)

    
if __name__ == '__main__':
    main()
