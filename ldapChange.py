#!/usr/bin/python

"""
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */
"""

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
cef_prod = 'Openldap Change'
cef_vers = '0.1'
cef_id = '4'
cef_sev = '4'


#logDir = '/home/eric/scripts/git/ldap-logs'
logDir = '/Users/eparker/scripts/git/ldap-logs'
logFile = logDir + '/auditlog.ldif-20130327'
logDb = logDir + '/change.db'

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
        print 'Exit: no name given'
        print cefblob.items()
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
          
        #lcef['cs2'] = change_type
        #lcef['cs2Label'] = 'changeType'
        
        lcef['cs3'] = mod_param
        lcef['cs3Label'] = 'modParameter'
        
        lcef['name'] = change_type + " " + mod_param
      
    else:
        print blob
        lcef['name'] = 'skip'

    return(lcef)
    cefit(lcef)

def parsefile(f_dump):
    # Set up the main data structure, values will default to a new string.
    log_minder = ''
    connections = defaultdict(str)
    
    
    for line in open(logFile):
        line = line.strip()
        # Start of a new change log
        start_match = re.search(start_reg,line)
        if start_match:
            change_id = start_match.group(2)
            mid_track = 'on'    

        if mid_track == 'on': # start collecting data within
            if line == '-':
                continue
            log_minder = log_minder + " -->" + line
            
            
        end=_modify = '# end modify ' + change_id
        end_add = '# end add ' + change_id
        if line == end_modify or line == end_add:
            # done with that log entry now parse it
            logfix = spank(log_minder)
            
            if logfix['name'] == 'skip':
                log_minder = ''
                print 'skipping'
                continue
            else:
                cefit(logfix)
                log_minder = ''
   
def getlastcount():
    fcheck = os.path.isfile(logDb)
    if fcheck:
        fdata = file(logDb).read()
        fdata = fdata.strip()
        sdata = str.split(fdata,'_')
        return sdata
    else:
        return ['0','0']
    
def getCountNow():
    with open(logFile) as f:
        for i, l in enumerate(f):
            pass
    return i + 1
  
def main():
    lastRunInfo = getlastcount()
    lastLine = int(lastRunInfo[1])
    
    nowCount = getCountNow()
    print nowCount
    print lastLine
    sys.exit()
    
    parsefile('stuff')
  
if __name__ == '__main__':
    main()
