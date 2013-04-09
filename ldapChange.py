#!/usr/bin/python

"""
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */
"""

# This script will parse the ldap change logs.

# Imports
from collections import defaultdict
import re
import sys
import os
import calendar
import syslog
import getopt

# Globals
cef_vend = 'mozilla'
cef_prod = 'Openldap Audit'
cef_vers = '0.5'
cef_id = '4'
cef_sev = '4'


#logDir = '/home/eric/scripts/git/ldap-logs'
#logDir = '/Users/eparker/scripts/git/ldap-logs'
logDir = '/var/lib/ldap/auditlogs'
logFile = logDir + '/auditlog.ldif'
logDb = logDir + '/audit-track.log'

## Regex
start_reg = re.compile(r'# (modify|add|delete)\s+(\d+).*')
dn_reg = re.compile(r'-->dn: mail=(.*?)\,.*')
id_reg = re.compile(r'--># (modify|add|delete) (\d+)\s+(.*?)\s+-->')
change_reg = re.compile(r'.*?-->changetype:\s+(\w+)\s+-->(replace|add|delete|employeeType|\w+):\s+(\w+).*')
date_reg = re.compile(r'(\d\d\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)')
emp_reg = re.compile(r'.*?cn:\s+(.*?)\s+-->')
mail_reg = re.compile(r'.*?mail:\s+(.*?)\s+-->')
changer_reg = re.compile(r'.*?modifiersName:\s+mail=(.*?)\,.*?')
timer_reg = re.compile(r'.*?-->modifyTimestamp:\s+(\d+)')
cs1Info_reg = re.compile(r'.*?-->changetype:\s+\w+\s+-->(\w+).*?-->(.*?)-->.*')
getDn_reg = re.compile(r'.*?-->dn:\s+(.*?)-->.*')

def logit(cef):
    syslog.openlog('ldapChanges', 0, syslog.LOG_LOCAL4)
    syslog.syslog(syslog.LOG_INFO, cef)
    syslog.closelog

def cefit(cefblob):
    log_ext = ''
    #print ''
    # Standard CEF
    #CEF header:
    #CEF:0|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|
    
    if cefblob['name']:
        cef_head =  'CEF:0|' + cef_vend + '|' + cef_prod + '|' + cef_vers + '|' + cef_id + '|' + cefblob['name'] + '|' + cef_sev + '|'
    else:
        #print 'Exit: no name given'
        #print cefblob.items()
        sys.exit()
    
    #Extenstions
    for log_key in cefblob.keys():
        if log_key == 'name':
            continue # Skip it this is in the header
        
        #clean up the '=' should be escaped just incase of cef stupidity
        blobdata = cefblob[log_key].replace('=','\=')
        log_ext = log_key + '=' + blobdata + ' ' + log_ext        
        
    #Pull em together for full CEF message, muha ha ha!
    cef_msg = cef_head + log_ext
    #print cef_msg
    logit(cef_msg)

  
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
    #print ''
    #print blob
   
    # find the id
    id_find = re.search(id_reg,blob)
    if id_find:
        lcef['cn1'] = eqclean(id_find.group(2))
        lcef['cn1Label'] = 'logId'
 
    user_find = re.search(dn_reg,blob)
    if user_find:
        lcef['duser'] = user_find.group(1)

    changerName = re.search(changer_reg,blob)
    if changerName:
        lcef['suser'] = changerName.group(1)
   
    modTime = re.search(timer_reg,blob)
    if modTime:
        change_date = datecef(modTime.group(1))
        lcef['end'] = change_date
        
    getCs1 = re.search(cs1Info_reg,blob)
    if getCs1:
        cs1set = getCs1.group(1) + ' ' + getCs1.group(2)
        lcef['cs1'] = cs1set
        lcef['cs1Label'] = 'changetype'
        
    getCs2 = re.search(getDn_reg,blob)
    if getCs2:
        cs2set = getCs2.group(1)
        lcef['cs2'] = cs2set
        lcef['cs2Label'] = 'fullDn'
        
    # find the change and modify name
    change_find = re.search(change_reg,blob)
    if change_find.group(1) == 'add' and (change_find.group(2) == 'employeeType' or change_find.group(2) == 'physicalDeliveryOfficeName'):
        change_type = change_find.group(1)
        lcef['cs2'] = 'Add Employee'
        lcef['cs2Label'] = 'changeType'
        lcef['name'] = 'add Employee'
        
        employeeName = re.search(emp_reg,blob)
        if employeeName:
            lcef['cs5'] = employeeName.group(1)
            lcef['cs5Label'] = 'fullName'
        
        employeeEmail = re.search(mail_reg,blob)
        if employeeName:
            lcef['cs6'] = employeeEmail.group(1)
            lcef['cs6Label'] = 'emailAddress'
        
    elif change_find.group(1) == 'modify':   
        change_type = change_find.group(1)
        mod_param = change_find.group(3)
        
        lcef['cs3'] = mod_param
        lcef['cs3Label'] = 'modParameter'
        
        lcef['name'] = change_type + " " + mod_param
      
    else:
        #print blob
        #CEF:0|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|
        blobFix = eqclean(blob)
        cef_head =  'CEF:0|' + cef_vend + '|' + cef_prod + '|' + cef_vers + '|' + cef_id + '|' + 'Unparsed Log' + '|' + cef_sev + '|'
        cef_ext = 'msg=' + blobFix
        
        unparsed = cef_head + cef_ext
        logit(unparsed)
        lcef['name'] = 'skip'

    return(lcef)
    cefit(lcef)

def parsefile(startAt):
    # Set up the main data structure, values will default to a new string.
    log_minder = ''      
    connections = defaultdict(str)
    logCount = 0
    mid_track = ''
    end_modify = ''
    end_add = ''
    change_id = ''
    
    for line in open(logFile):
        logCount = logCount + 1
        
        if logCount < startAt and startAt != 0:
            #logCount = logCount + 1
            continue

        
        line = line.strip()
        # Start of a new change log
        start_match = re.search(start_reg,line)
        if start_match:
            change_id = start_match.group(2)
            mid_track = 'on'    
        #else:
        #    continue

        if mid_track == 'on': # start collecting data within
            if line == '-':
                continue
            log_minder = log_minder + " -->" + line
            
            
        end_modify = '# end modify ' + change_id
        end_add = '# end add ' + change_id
        end_delete = '# end delete ' + change_id
        if line == end_modify or line == end_add or line == end_delete:
            # done with that log entry now parse it
            logfix = spank(log_minder)
            
            if logfix['name'] == 'skip':
                log_minder = ''
                continue
            else:
                cefit(logfix)
                log_minder = ''
        
        #logCount = logCount + 1

    countStr = str(logCount)
    db_f = open(logDb, 'w')
    db_f.write(countStr)
    db_f.close()
    #print logCount
   
def getlastcount():
    fcheck = os.path.isfile(logDb)
    if fcheck:
        fdata = file(logDb).read()
        fdata = fdata.strip()
        
        if not fdata:
            return 0
        
        return fdata
    else:
        return 0
    
def getCountNow():
    with open(logFile) as f:
        for i, l in enumerate(f):
            pass
    return i + 1

def figureStart():
    #lastRunInfo = getlastcount()
    lastCount = int(getlastcount())
    nowCount = int(getCountNow())  
   
    if lastCount == 0 or nowCount == 0:
        return 0
    elif nowCount == lastCount:
        cef_head =  'CEF:0|' + cef_vend + '|' + cef_prod + '|' + cef_vers + '|' + cef_id + '|' + 'Run Started No Changes to Log' + '|' + cef_sev + '|'
        cef_ext = 'msg=Script ran successfully however no addtional updates to the log was written since last run'
        nolog = cef_head + cef_ext
        logit(nolog)
        sys.exit(6) # The file has not changed give up here

    elif nowCount > lastCount:
        return int(lastCount)
    elif nowCount < lastCount:
        return 0
    else:
        return 0 
    #sys.exit()

def usage():
    print '\nldapChange.py   -e process everything in the db file\n\t\t-i process the db file starting from last run stop'
  
def main(argv):
    run_type = 'inc'
    try:
       opts, args = getopt.getopt(argv,"eih")
    except getopt.GetoptError:
       usage()
       sys.exit(2)
    
    optCount = len(opts)
    if optCount > 1:
        print '\nYou have to many arguments, either e or i'
        usage()
        sys.exit()
        
    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()
        elif opt == '-i':
            runStart = figureStart()
        elif opt == '-e':
            runStart = 0
        else:
            runStart = 0
    
    
    parsefile(runStart)
  
if __name__ == '__main__':
    main(sys.argv[1:])

