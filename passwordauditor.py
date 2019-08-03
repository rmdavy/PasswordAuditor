#!/usr/bin/python3

import os, signal, sys, re, string, readline
from collections import Counter

drsuapihash_list = []
enabledusers_list = []
priv_accounts_list = []
hashcat_output_list = []
complexity_list = []

enabledusers_drsuapihash_list = []
lm_accounts_list = []
blankpasswordscrackpassword_list = []
crackedpasswords_list = []
duplicate_drsuapi_list = []

buffer_list = []
options = []

# Exit Program
def quit():
	#exit
	sys.exit(0)

def banner():
	os.system('clear')

	print ("""
   ___                                    _     _             _ _ _             
  / _ \\__ _ ___ _____      _____  _ __ __| |   /_\\  _   _  __| (_) |_ ___  _ __ 
 / /_)/ _` / __/ __\\ \\ /\\ / / _ \\| '__/ _` |  //_\\\| | | |/ _` | | __/ _ \\| '__|
/ ___/ (_| \\__ \\__ \\\ V  V / (_) | | | (_| | /  _  \\ |_| | (_| | | || (_) | |   
\\/    \\__,_|___/___/ \\_/\\_/ \\___/|_|  \\__,_| \\_/ \\_/\\__,_|\\__,_|_|\\__\\___/|_|   
                                                                                
	""")

	print ("Password Auditor 1.0 - By Richard DAVY")
	print ("@rd_pentest\n")

def checkfiles():
	#Routine checks the dump folder for four files
	#/drsuapi_gethashes.txt
	#/enabled_accounts.txt
	#/hashcat_output.txt
	#/priv_accounts.txt
	#If they're found sets the global variable with their location

	global drsuapi_gethashes
	global enabled_accounts
	global hashcat_output
	global priv_accounts

	drsuapi_gethashes=""
	enabled_accounts=""
	hashcat_output=""
	priv_accounts=""

	if os.path.isfile(DumpFolder+"/drsuapi_gethashes.txt"):
		print ("[*] Found drsuapi_gethashes.txt")
		drsuapi_gethashes=DumpFolder+"/drsuapi_gethashes.txt"
	else:
		print ("[!] Not Found - drsuapi_gethashes.txt")
		error_menu()

	if os.path.isfile(DumpFolder+"/enabled_accounts.txt"):
		print ("[*] Found enabled_accounts.txt")
		enabled_accounts=DumpFolder+"/enabled_accounts.txt"
	else:
		print ("[!] Not Found - enabled_accounts.txt")

	if os.path.isfile(DumpFolder+"/hashcat_output.txt"):
		print ("[*] Found hashcat_output.txt")
		hashcat_output=DumpFolder+"/hashcat_output.txt"
	else:
		print ("[!] Not Found - hashcat_output.txt")

	if os.path.isfile(DumpFolder+"/priv_accounts.txt"):
		print ("[*] Found priv_accounts.txt")
		priv_accounts=DumpFolder+"/priv_accounts.txt"
	else:
		print ("[!] Not Found - priv_accounts.txt")

def readinfiles():
	#Routine reads in all of the files from
	#check files routine and populates the various lists
	
	#Clear out our lists incase files get reloaded
	drsuapihash_list.clear()
	enabledusers_list.clear()
	hashcat_output_list.clear()
	priv_accounts_list.clear()

	#Read in hashes from drsuapi file
	#regex to make sure they're valid hashes
	if drsuapi_gethashes!="":
		with open(drsuapi_gethashes) as fp:
			for line in fp:
				#Regex to check that it's a recognised hash
				pwdumpmatch = re.compile('^(\S+?):.*?:([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::\s*$')
				pwdump = pwdumpmatch.match(line)
				if pwdump:
					if not "$" in str(pwdump):
						#If the username contains the domain, strip it out
						if "\\" in str(pwdump):
							result=line.find("\\")
							drsuapihash_list.append(line[result+1:].rstrip())
						else:
							drsuapihash_list.append(line.rstrip())

	#Read in all of the usernames for enabled accounts
	if enabled_accounts!="":
		with open(enabled_accounts) as fp:
			for line in fp:
				enabledusers_list.append(line.rstrip())

		#Parse the drsuapi hash list for only acccount names which are 
		#enabled and create new list to work with
		gen_enableduser_drsuapi_gethashes()

	#Read in all of the hashcat output in
	if hashcat_output!="":
		with open(hashcat_output) as fp:
			for line in fp:
				#If the username contains the domain, strip it out
				if "\\" in str(line):
					result=line.find("\\")
					hashcat_output_list.append(line[result+1:].rstrip())
				else:
					hashcat_output_list.append(line.rstrip())

	#Read in all of the privileged account names in
	if priv_accounts!="":
		with open(priv_accounts) as fp:
			for line in fp:
				priv_accounts_list.append(line.rstrip())

def gen_enableduser_drsuapi_gethashes():
	#Parse the drsuapi hash list for only acccount names which are 
	#enabled and create new list to work with
	print("[*]Extracting list of Enabled users from drsuapi_gethashes.txt file")

	for username in enabledusers_list:
		for user in drsuapihash_list:

			strippedusername=user[:user.find(":")]

			if username == strippedusername:
				enabledusers_drsuapihash_list.append(user)

def write_enabled_accountlist_for_hashcat():
	#generate an enabled account list for hashcat - no point cracking passwords for disabled accounts
	if len(enabledusers_drsuapihash_list)>0:
		fout=open(DumpFolder+"/pwa_enabled_user_hashes.txt",'w')
		#Write details to file
		for x in enabledusers_drsuapihash_list:
			fout.write(x+"\n")
		#Close handle
		fout.close()

		banner()
		print("[*]"+str(len(enabledusers_drsuapihash_list))+" accounts written to "+DumpFolder+"/pwa_enabled_user_hashes.txt")
	else:
		print("[!]No enabled account data available")

	sub_menu()

def lmaccounts():
	#extract accounts which have a LM hash
	
	banner()
	lm_accounts_list.clear()

	for item in drsuapihash_list:
		if not item.split(":")[2]=="aad3b435b51404eeaad3b435b51404ee":
			lm_accounts_list.append(item)

	print ("[*]"+str(len(lm_accounts_list))+" LM user accounts found in " + str(drsuapi_gethashes)+"\n") 
	
	if len(lm_accounts_list)>0:
		for lmuser in lm_accounts_list:
			print (lmuser)

		#Write out the full hash details to file
		fout=open(DumpFolder+"/pwa_lm_hashes.txt",'w')
		#Write details
		for x in lm_accounts_list:
			fout.write(x+"\n")
		#Close handle
		fout.close()

		print("\n[*]"+str(len(lm_accounts_list))+" LM user accounts written to "+DumpFolder+"/pwa_lm_hashes.txt")

		#Write out just the usernames to file
		fout=open(DumpFolder+"/pwa_lm_usernames.txt",'w')
		#Write details
		for x in lm_accounts_list:
			fout.write(x.split(":")[0]+"\n")
		#Close handle
		fout.close()

		print("[*]"+str(len(lm_accounts_list))+" LM usernames written to "+DumpFolder+"/pwa_lm_usernames.txt")

	else:
		print("[!]No LM hashes were detected")

	sub_menu()

def blank_passwords_cracked_passwords():
	#Check HashCat output for blank passwords
	banner()
	blankpasswordscrackpassword_list.clear()

	if len(hashcat_output_list)!=0:
		#extract accounts which have a blank password
		for item in hashcat_output_list:
			if item.split(":")[2]=="":
				blankpasswordscrackpassword_list.append(item)

		print ("[*]Blank Password User Accounts found in " + str(hashcat_output)+"\n") 
		for blankuser in blankpasswordscrackpassword_list:
			print (blankuser)

		fout=open(DumpFolder+"/pwa_blank_password_accounts.txt",'w')
		#Write details
		for x in blankpasswordscrackpassword_list:
			fout.write(x+"\n")
		#Close handle
		fout.close()

		print("\n[*]Blank user accounts written to "+DumpFolder+"/pwa_blank_password_accounts.txt")

	else:
		print("[!]No HashCat data available")

	sub_menu()

def cracked_usernames_enabled():
	#Check HashCat output for cracked usernames
	banner()
	buffer_list.clear()

	if len(hashcat_output_list)!=0:
		#extract cracked username
		for item in hashcat_output_list:
			#Add condition here for enabled or not
			for euser in enabledusers_list:
				if euser==item.split(":")[0]:
					buffer_list.append(item.split(":")[0])

		print ("[*]Cracked & enabled usernames found in " + str(hashcat_output)+"\n") 
		for item in buffer_list:
			print(item)

		#Output details to file.
		fout=open(DumpFolder+"/pwa_cracked_enabled_usernames.txt",'w')
		#Write details
		for x in buffer_list:
			fout.write(x+"\n")
		#Close handle
		fout.close()

		print("\n[*]Cracked and enabled user account names written to "+DumpFolder+"/pwa_cracked_enabled_usernames.txt")

	else:
		print("[!]No HashCat data available")

	sub_menu()


def cracked_usernames():
	#Check HashCat output for cracked usernames
	banner()
	buffer_list.clear()

	if len(hashcat_output_list)!=0:
		#extract cracked username
		for item in hashcat_output_list:
			buffer_list.append(item.split(":")[0])

		print ("[*]Cracked usernames found in " + str(hashcat_output)+"\n") 
		for item in buffer_list:
			print(item)

		#Output details to file.
		fout=open(DumpFolder+"/pwa_cracked_usernames.txt",'w')
		#Write details
		for x in buffer_list:
			fout.write(x+"\n")
		#Close handle
		fout.close()

		print("\n[*]Cracked user account names written to "+DumpFolder+"/pwa_cracked_usernames.txt")

	else:
		print("[!]No HashCat data available")

	sub_menu()


def mostfrequentpasswords():
	#most frequest passwords
	banner()
	crackedpasswords_list.clear()

	if len(hashcat_output_list)!=0:
		for item in hashcat_output_list:
			if item.split(":")[2]!="":
				crackedpasswords_list.append(item.split(":")[2])

		crackedpasswords_list_unique=set(crackedpasswords_list)

		print ("[*]Top 20 Passwords found in " + str(hashcat_output)+"\n") 

		print ("[*]"+str(len(crackedpasswords_list))+" Total Passwords found in " + str(hashcat_output)) 
		print ("[*]"+str(len(crackedpasswords_list_unique))+" Unique Passwords found in " + str(hashcat_output)+"\n") 

		a = Counter(crackedpasswords_list)
		for letter, count in a.most_common(20):
			#print to screen
			print (letter, str(count) + " instances")
	

		fout=open(DumpFolder+"/pwa_most_frequent.txt",'w')
		#Write details
		for letter, count in a.most_common(20):
			fout.write(str((letter, str(count) + " instances"))+"\n")
		#Close handle
		fout.close()

		print("\n[*]Most frequent 20 passwords written to "+DumpFolder+"/pwa_most_frequent.txt")

	else:
		print("[!]No HashCat data available")

	sub_menu()

def privileged_cracked_enabled_accounts():
	#Find Accounts which are
	# 1 in the privileged accounts list
	# 2 have been cracked
	# 3 are enabled in AD	

	banner()
	print ("[*]Privileged, Cracked and Enabled Accounts "+"\n") 
	
	buffer_list.clear()

	if len(enabledusers_list)>0:
		#Start by getting privilaged account names
		for pitem in priv_accounts_list:
			priv_username=pitem.split(":")[0]
			#Get the hashcat usernames
			for hitem in hashcat_output_list:
				hash_username=hitem.split(":")[0]
				#If priv account name is in hashcat name list
				#then check if it's enabled
				if len(priv_accounts_list)>0:
					if priv_username==hash_username:
						for en_username in enabledusers_list:
							if en_username==hash_username:
								buffer_list.append(hash_username)
				else:
					print("[!]Privileged users list not available")

		
		for item in buffer_list:
			print(item)

		fout=open(DumpFolder+"/pwa_pr_cr_en.txt",'w')
		#Write details
		for x in buffer_list:
			fout.write(x+"\n")
		#Close handle
		fout.close()

		print("\n[*]Privileged, Cracked and Enabled Accounts written to "+DumpFolder+"/pwa_pr_cr_en.txt")

	else:
		print("[!]Enabled users list not available")

	sub_menu()

def privileged_cracked():
	#Find Accounts which are
	# 1 in the privileged accounts list
	# 2 have been cracked

	banner()
	print ("[*]Privileged & Cracked "+"\n") 

	buffer_list.clear()

	if len(priv_accounts_list)>0:
		for pitem in priv_accounts_list:
			priv_username=pitem.split(":")[0]
			
			for hitem in hashcat_output_list:
				hash_username=hitem.split(":")[0]
			
				if priv_username==hash_username:
					buffer_list.append(hash_username)

		for item in buffer_list:
			print(item)

		fout=open(DumpFolder+"/pwa_pr_cr.txt",'w')
		#Write details
		for x in buffer_list:
			fout.write(x+"\n")
		#Close handle
		fout.close()

		print("\n[*]Privileged, Cracked Accounts written to "+DumpFolder+"/pwa_pr_cr.txt")
	
	else:
		print("[!]Privileged users list not available")

	sub_menu()

def does_cracked_account_meet_password_complexity_requiremnts():
	#Routine checks cracked passwords from hashcat output
	#against Password requirements, Length, Complexity
	#Default is 8 characters can be changed by user
	
	#Display banner
	banner()
	#Clear list incase of previous run
	complexity_list.clear()
	#Check hashcat output has been loaded
	if len(hashcat_output_list)!=0:
		#Print msg to screen
		print ("[*]Password Complexity Requirements Check for " + str(hashcat_output)+"\n") 
		#get the minimum password length from use
		minpasswordlength = int(input("Minimum Password Length Requirement (default 8) : ") or "8")
		#Set ccheck buffer to 0 ready for calculations
		ccheck=0
		#Loop though password in hashcat output
		for password in hashcat_output_list:
			count=0
			#Parse the password from the end of the line
			line=password.split(":")[2].rstrip()

			#Check the password length against the minimum variable if not met add to list
			if len(line)<minpasswordlength:
				complexity_list.append("Too Short " + password.split(":")[0].rstrip()+" "+line)
				ccheck+=1	
			else:
				#Check for numbers
				if re.search('([0-9])', line, flags=0):
					count+=1
				#Check for lowercase alpha
				if re.search('([a-z])', line, flags=0):
					count+=1
				#Check for uppercase alpha
				if re.search('([A-Z])', line, flags=0):
					count+=1
				#Check for specials
				if re.search('([\W_])', line, flags=0):
					count+=1
				#If count is less than 3 complexity has not been met
				#if it's not met add to the list
				if count<3:
					complexity_list.append("Complexity requirements not met " + password.split(":")[0].rstrip() + " "+line)
					ccheck+=1

		#Sort the list alphabetically
		complexity_list.sort()
		#iterate through the list and print to screen
		for item in complexity_list:
			print(item)

		#Write the list contents out to file
		fout=open(DumpFolder+"/pwa_complexity.txt",'w')
		for x in complexity_list:
			fout.write(x+"\n")
		#Close handle
		fout.close()

		#Print msg out to screen
		print("\n[*]Password complexity details written to "+DumpFolder+"/pwa_complexity.txt")
	else:
		print("[!]No HashCat data available")

	sub_menu()

def enabled_duplicate_hashes_cracked_privs():
	#check for duplicate hashes on enabled accounts
	#append cracked - hashcat_output
	#append privs - priv_accounts_list

	banner()
	print("[*]Enabled users with duplicate hashes found in " + str(drsuapi_gethashes)+"\n") 
	result=input("[?]Display Cracked password where found (Y/N) ") or "Y"
	print("\n[*]Be patient this can take some time\n")

	duplicate_drsuapi_list.clear()

	if len(enabledusers_drsuapihash_list)>0:
		for hitem in enabledusers_drsuapihash_list:
			
			check_duplicates_list=0
			for ditem in duplicate_drsuapi_list:
				if hitem==ditem:
					check_duplicates_list=1

			if check_duplicates_list==0:
				buffer_list.clear()
				nthash=hitem.split(":")[3]
				for citem in enabledusers_drsuapihash_list:
					nthash_tomatch=citem.split(":")[3]

					if nthash==nthash_tomatch:
						buffer_list.append(citem)

				buffer_list_unique=set(buffer_list)
				if len(buffer_list_unique)>1:
					duplicate_drsuapi_list.append("")
					for bitem in buffer_list_unique:
						#print(bitem)
						duplicate_drsuapi_list.append(bitem)

		#Iterate the duplicate list and check them against the priv list
		for i in range(len(duplicate_drsuapi_list)):
			dup_username=duplicate_drsuapi_list[i].split(":")[0]
			#Check whether item is in priv list
			if len(priv_accounts_list)>0:
				for pitem in priv_accounts_list:
					priv_username=pitem.split(":")[0]
					if dup_username==priv_username:
						duplicate_drsuapi_list[i]=duplicate_drsuapi_list[i]+"*Privileged*:"

		#Iterate the duplicate list and check them against the cracked list
		for i in range(len(duplicate_drsuapi_list)):
			dup_username=duplicate_drsuapi_list[i].split(":")[0]
			#Check whether item is in priv list
			if len(hashcat_output_list)>0:
				for hitem in hashcat_output_list:
					#print(hitem)
					hash_username=hitem.split(":")[0]
					#print(hash_username)

					if dup_username==hash_username:
						if result.upper()=="Y":
							duplicate_drsuapi_list[i]=duplicate_drsuapi_list[i]+hitem.split(":")[2]+":"
						else:
							duplicate_drsuapi_list[i]=duplicate_drsuapi_list[i]+"*Password Cracked*:"

		#Print data to screen
		for uitem in duplicate_drsuapi_list:
			print(uitem)

		#Write data to file
		fout=open(DumpFolder+"/pwa_hashmatch_ecp.txt",'w')
		#Write details
		for x in duplicate_drsuapi_list:
			fout.write(x+"\n")
		#Close handle
		fout.close()

		print("\n[*]Enabled users with duplicate hashes written to "+DumpFolder+"/pwa_hashmatch_ecp.txt")

	else:
		print("[!]Enabled user data not available")

	sub_menu()

def enabled_duplicate_hashes():
	#checkfor duplicate hashes on all accounts
	#duplicate_drsuapi_list
	#drsuapihash_list
	#enabledusers_drsuapihash_list

	banner()
	print("[*]Enabled users with duplicate hashes found in " + str(drsuapi_gethashes)+"\n") 
	print("[*]Be patient this can take some time\n")

	duplicate_drsuapi_list.clear()

	#Check list of enabled user hashes is greater than 0
	if len(enabledusers_drsuapihash_list)>0:
		#start a loop of these users
		for hitem in enabledusers_drsuapihash_list:
			#reset duplicate flag to 0
			check_duplicates_list=0
			for ditem in duplicate_drsuapi_list:
				if hitem==ditem:
					check_duplicates_list=1

			if check_duplicates_list==0:
				buffer_list.clear()
				nthash=hitem.split(":")[3]
				for citem in enabledusers_drsuapihash_list:
					nthash_tomatch=citem.split(":")[3]

					if nthash==nthash_tomatch:
						buffer_list.append(citem)

				buffer_list_unique=set(buffer_list)
				if len(buffer_list_unique)>1:
					duplicate_drsuapi_list.append("")
					for bitem in buffer_list_unique:
						#print(bitem)
						duplicate_drsuapi_list.append(bitem)

		#Print items to screen
		for ditem in duplicate_drsuapi_list:
			print(ditem)

		#Write data to file
		fout=open(DumpFolder+"/pwa_hashmatch_e.txt",'w')
		#Write details
		for x in duplicate_drsuapi_list:
			fout.write(x+"\n")
		#Close handle
		fout.close()

		print("\n[*]Enabled users with duplicate hashes written to "+DumpFolder+"/pwa_hashmatch_e.txt")

	else:
		print("[!]Enabled user data not available")

	sub_menu()

def all_duplicate_hashes():
	#checkfor duplicate hashes on all accounts
	#duplicate_drsuapi_list
	#drsuapihash_list
	#enabledusers_drsuapihash_list

	banner()
	print ("[*]Duplicate hashes found in " + str(drsuapi_gethashes)+"\n") 
	print("[*]Be patient this can take some time\n")

	duplicate_drsuapi_list.clear()

	if len(drsuapihash_list)>0:
		for hitem in drsuapihash_list:
			
			check_duplicates_list=0
			for ditem in duplicate_drsuapi_list:
				if hitem==ditem:
					check_duplicates_list=1

			if check_duplicates_list==0:
				buffer_list.clear()
				nthash=hitem.split(":")[3]
				for citem in drsuapihash_list:
					nthash_tomatch=citem.split(":")[3]

					if nthash==nthash_tomatch:
						buffer_list.append(citem)

				buffer_list_unique=set(buffer_list)
				if len(buffer_list_unique)>1:
					duplicate_drsuapi_list.append("")
					for bitem in buffer_list_unique:
						#print(bitem)
						duplicate_drsuapi_list.append(bitem)

		for ditem in duplicate_drsuapi_list:
			print(ditem)

		#Write data to file
		fout=open(DumpFolder+"/pwa_hashmatch.txt",'w')
		#Write details
		for x in duplicate_drsuapi_list:
			fout.write(x+"\n")
		#Close handle
		fout.close()

		print("\n[*]Enabled users with duplicate hashes written to "+DumpFolder+"/pwa_hashmatch.txt")
	else:
		print("[*]drsuapi_gethashes hashes not available")

	sub_menu()

def main_menu():
	#Print menu to screen
	while(1):
		print("\n")
		print("(0)\tExtract LM Accounts in drsuapi_gethashes.txt")
		print("(1)\tExtract enabled user account hashes from drsuapi_gethashes.txt")
		print("(2)\tDisplay Top 20 Passwords in hashcat_output.txt")
		print("(3)\tCheck Complexity Requirements for accounts in hashcat_output.txt")
		print("(4)\tDisplay Accounts with Blank Password in hashcat_output.txt")
		print("(5)\tCheck Privileged & Enabled Accounts against hashcat_output.txt")
		print("(6)\tCheck Privileged Accounts against hashcat_output.txt")
		print("(7)\tFind Enabled users with same password")
		print("(8)\tFind All users with same password")
		print("(9)\tFind Enabled/Cracked/Privileged users with same password")

		print("(10)\tExtract list of cracked usernames from hashcat_output.txt")
		print("(11)\tExtract list of cracked & enabled usernames from hashcat_output.txt")

		print("(18)\tReload files")
		print("(19)\tLoad files from new location")
		print("(20)\tQuit")
		
		#User options
		options.insert(0,lmaccounts)
		options.insert(1,write_enabled_accountlist_for_hashcat)
		options.insert(2,mostfrequentpasswords)
		options.insert(3,does_cracked_account_meet_password_complexity_requiremnts)
		options.insert(4,blank_passwords_cracked_passwords)
		options.insert(5,privileged_cracked_enabled_accounts)
		options.insert(6,privileged_cracked)
		options.insert(7,enabled_duplicate_hashes)
		options.insert(8,all_duplicate_hashes)
		options.insert(9,enabled_duplicate_hashes_cracked_privs)
		options.insert(10,cracked_usernames)
		options.insert(11,cracked_usernames_enabled)
		options.insert(12,"")
		options.insert(13,"")
		options.insert(14,"")
		options.insert(15,"")
		options.insert(16,"")
		options.insert(17,"")
		
		options.insert(18,reloadfiles)
		options.insert(19,loadfiles)
		options.insert(20,quit)

		#Get a menu selection from the user and then call the list item
		#Catch most possible errors due to user entry
		try:
			task = input("\nSelect a task: ") or "20"
			options[int(task)]()
		except KeyError:
			pass
			banner()
			main_menu()
		except ValueError:
		# handle ValueError exception
			pass
			banner()
			main_menu()
		except IndexError:
		# handle ValueError exception
			pass
			banner()
			main_menu()
		except (TypeError, ZeroDivisionError):
		# handle multiple exceptions
		# TypeError and ZeroDivisionError
			banner()
			main_menu()
			pass

def reset_screen():
	banner()
	main_menu()

def reloadfiles():

	banner()

	print ("\n")
	checkfiles()
	
	print ("\n")
	readinfiles()

	main_menu()

def loadfiles():
	#Routine gets location from the user of where the necessary files are stored
	#if the user just presses enter, the current working directory is used

	global DumpFolder
	DumpFolder=input ("[*]Please enter folder location of files to process: ") or (os.getcwd())
	#Print banner to screen
	banner()

	print ("\n")
	#Call check files
	checkfiles()
	
	print ("\n")
	#Call read in files
	readinfiles()
	#Load main menu
	main_menu()

def sub_menu():
	#Print menu to screen
	while(1):
		print("\n")
		print("(0)\tReturn to Main Menu")
		
		#User options
		options.insert(0,reset_screen)
		
		#Process the selected option
		try:
			task = input("\nSelect a task: ") or "0"
			options[int(task)]()
		except KeyError:
			pass

def error_menu():
	#Print menu to screen
	while(1):
		print("\n")
		
		#User options
		print("(0)\tLoad files from new location")
		print("(1)\tQuit")

		#User options
		options.insert(0,loadfiles)
		options.insert(1,quit)
		
		#Process the selected option
		try:
			task = input("\nSelect a task: ") or "0"
			options[int(task)]()
		except KeyError:
			pass

def main():
	#Print banner to screen
	banner()
	#Display basic help information
	print("Usage:\n")
	print("Create a folder which contains the following files\n")
	print("drsuapi_gethashes.txt - list of hashes dumped from a Domain Controller")
	print("enabled_accounts.txt - (Optional) list of enabled user accounts ")
	print("hashcat_output.txt - (Optional) hashcat cracked password output, including usernames")
	print("priv_accounts.txt - (Optional) list of privileged domain accounts\n")
	#Start trying to load files
	loadfiles()

#Routine handles Crtl+C
def signal_handler(signal, frame):
	print ("\nCtrl+C pressed.. exiting...")
	sys.exit()

if __name__ == '__main__':
	#Setup Signal handler in case of Ctrl+C
	signal.signal(signal.SIGINT, signal_handler)
	#Call main routine.
	main()
