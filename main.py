import win32evtlog # requires pywin32 pre-installed
import subprocess
from datetime import datetime, timedelta, date

server = 'localhost' # name of the target computer to get event logs
logtype = 'Security'
hand = win32evtlog.OpenEventLog(server,logtype)
flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
total = win32evtlog.GetNumberOfEventLogRecords(hand)

groupSuffix = "" # Suffix/Prefix common for all AD Groups used in Radius Authentication
ou = "" # OU where to create MacAddress Users ex "OU=MacRadiusUsers,OU=ServiceUsers,DC=local,DC=com"
accountExpire = 7 # days
domain = "" # Domain name ex "local.com"

def getLastFailedRadiusLogon():
    i = True
    temp = []
    while i:
        events = win32evtlog.ReadEventLog(hand, flags,0)
        if events:
            event = events[0]
            if str(event.EventID) == "6273": # ID Event for unauthorized user event
                data = event.StringInserts
                if data:
                    for msg in data:
                        temp.append(msg)
                i = False
    return temp[1]

def checkADCredentials(username, password):
    cmd = '$CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName \
    $domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,"%s","%s") \
    if ($domain.name -eq $null) { \
    write-host "Failed" \
    } else {write-host "Success"}' % (username, password)
    completed = subprocess.run(["powershell", "-Command", cmd], capture_output=True)
    if "Success" in str(completed):
        return True
    else:
        return False

def createADUser(username, macaddress):
    s = date.today()
    expireDate = s + timedelta(days=accountExpire)
    expireDate = expireDate.strftime("%m/%d/%Y")

    cmd = 'New-ADUser -Name %s -Accountpassword (ConvertTo-SecureString -AsPlainText %s -Force) -UserPrincipalName "%s@%s" -SamAccountName %s -GivenName %s -Surname "MAC Address" -path "%s" -Enabled $true -AccountExpirationDate %s -CannotChangePassword $True' % (macaddress, macaddress, macaddress, macaddress, domain, username, ou, expireDate) #Create AD User with MAC Address as Username and Password
    completed = subprocess.run(["powershell", "-Command", cmd], capture_output=True)
    print(completed)

def getUserRadiusGroup(username):
    cmd = 'Get-ADPrincipalGroupMembership %s | select name' % (username)
    completed = subprocess.run(["powershell", "-Command", cmd], capture_output=True)
    completed = str(completed).split("\\r\\n")
    radiusGroups = [s.rstrip() for s in completed if groupSuffix in s]
    print(radiusGroups)
    return radiusGroups

def addUserToGroup(macaddress, username):
    radiusGroups = getUserRadiusGroup(username)
    for group in radiusGroups:
        cmd = 'Add-ADGroupMember -Identity "%s" -Members %s' % (group, macaddress)
        completed = subprocess.run(["powershell", "-Command", cmd], capture_output=True)
    return completed

username = "" # AD Username
password = "" # AD Password

if checkADCredentials(username, password):
    macaddress = getLastFailedRadiusLogon()
    createADUser(username, macaddress)
    addUserToGroup(macaddress, username)
