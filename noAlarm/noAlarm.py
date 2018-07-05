import sys;
import r2pipe;
import json;
import os;
from termcolor import colored;


def patchAlarm(r2p,os,addr):
	if os['bits'] == 32:
		print colored ('[+] patching alarm','green');
		r2p.cmd('wx 31c0341e90 @{0}'.format(addr))#//xor rax,rax;xorb al,30;
	elif os['bits'] == 64:
		print colored('[+] patching alarm','green');
		r2p.cmd('wx 4831c0341e @{0}'.format(addr));#//xor rax,rax;xorb al,30;

def getArch(r2p):
	os = {};
	info = r2p.cmdj('ij')['bin'];
	os['bits'] = info['bits'];
	os['os'] = info['os'];
	if os['os'] != 'linux':
		print colored('[!] This module does not work on Windows','red');
		quit();
	return os;

def int2addr(num):
	return os.popen('rax2 {0}'.format(num)).read().strip();

def getAlarmCalls(r2p,os):
	alarmCalls = r2p.cmdj('axtj sym.imp.alarm');
	
	for call in alarmCalls:
		if call['type'] != 'C':
			print colored('[!] Warning {0} alarm data reference'.format(int2addr(call['from'])),'red');
		else:
			print colored('[+] found {0} alarm code reference'.format(int2addr(call['from'])),'green');
			patchAlarm(r2p,os,call['from']);	
def init(r2p):
	r2p.cmd('aa;aac');

def commit(r2p):
	r2p.cmd('wci');

def main():
	r2p = r2pipe.open();
	init(r2p);
	os = getArch(r2p);
	getAlarmCalls(r2p,os);
	commit(r2p);

if __name__ == '__main__':
	main();
	
