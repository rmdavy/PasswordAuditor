# PasswordAuditor

![PasswordAuditor](https://github.com/rmdavy/PasswordAuditor/blob/master/password_auditor.png)

Password Auditor is a tool to help pentesters quickly generate useful statistics as part of a domain password audit. 

This project originally started with HashMatch which is in another repo but when rewriting in Python3 morphed into including a number of other outputs.

Usage:
Start Password Auditor using
python3 passwordauditor.py

Password Auditor with then request the folder location of four input files which are as per below

drsuapi_gethashes.txt - A dump of the domain hashes
enabled_accounts.txt - (Optional) A list of enabled users in the domain (one entry per line)
hashcat_output.txt - (Optional) HashCat cracked password output including usernames
priv_accounts.txt - (Optional) A list of privileged accounts in the domain (one entry per line)

Password Auditor is menu driven so once it's loaded it's pretty straight forward.

Any issues, tweet me at @rd_pentest
