#!/usr/bin/python
####
#Author Kyle Martin
#A simple script to help with saving Reverse Engineering work in R2.
#profiles never seem to work and always seems to erase my variable renames, funcion renames,
#and custom flags.  will dump and save current work to a json file.  Should work with PIE enable
#executables.
####
import r2pipe
import sys
import json
from termcolor import colored

program = {
	"path": "",
	"func" : {},
	"comments" : [],
	"flags" : []
}


def perror(msg):
	print colored(msg,'red');

def pgood(msg):
	print colored(msg,'green');

def pinfo(msg):
	print colored(msg,'blue');


###
#Todo Error Checking
###
def saveDump(myfile):
	lastindex = myfile.rindex("/");
	dumpDir = myfile[:lastindex+1]
	with open(dumpDir + 'restoreDump.json', 'w') as fout:
		json.dump(program,fout);

	return True;

###
#ToDo Error Checking
###
def readDump(myfile):
	lastindex = myfile.rindex("/");
	dumpDir = myfile[:lastindex+1]
	with open(dumpDir + 'restoreDump.json','r') as fin:
		global program
		program = json.load(fin);

	return True;

def restoreFunctions(r,baseAddr):
	pinfo("Loading Functions");
	for kfcn, vfcn in program["func"].iteritems():
		out = "af {0} {1}".format(kfcn,hex(vfcn['offset']+baseAddr))
		pgood(out);
		r.cmd(out);

def restoreComments(r,baseAddr):
	pinfo("Loading Comments");
	for c in program["comments"]:
		out = "{0} {1} @ {2}".format(c["type"],c["name"],hex(c["offset"] + baseAddr));
		pgood(out);
		r.cmd(out);

def restoreFlags(r,baseAddr):
	pinfo("Loading Flags");
	for f in program["flags"]:
		out = "f {0} {1} @ {2}".format(f["name"],f["size"],hex(f["offset"] + baseAddr));
		pgood(out);
		r.cmd(out);

###
#Have to make sure you are looking at the function in VVV mode
###
def loadLocalVars(r):
	funcName = r.cmd("afa");
	

	if not funcName in program["func"].keys():
		perror("Save and reload your work");
		return;

	pinfo("Loading variables for " + funcName);

	for dName, info in program["func"][funcName]["vars"].iteritems():
		out = 'afvn {0} {1}'.format(dName,info["name"]);
		pgood(out);
		r.cmd(out);

###
#Make sure you are looking at the function in VVV mode
###
def saveLocalVars(r):
	funcName = r.cmd("afa");

	if not funcName in program["func"].keys():
		perror("Save and reload your work");
		return;

	pinfo("Saving var renames for " + funcName);
		
	var = r.cmdj("afvj");
	for vbp in var["bp"]:
		offset = hex(abs(vbp["ref"]["offset"]));
		defaultName = "local_{0}h".format(offset[2:]);
		pgood("Saving rename of " + defaultName + " as " + vbp["name"]);
		program["func"][funcName]["vars"][defaultName] = {
			"name" : vbp["name"],
			"kind" : vbp["kind"],
			"type" : vbp["type"]
		}
	print program["func"][funcName];
	saveDump(program["path"]);
	

def saveFlags(r,startAddr,endAddr):
	pinfo("Saving Flags");
	flags = r.cmdj("fj");
	program["flags"] = [];
	for f in flags:
		if f["offset"] >= startAddr and f["offset"] <= endAddr:
			pgood(hex(f["offset"]) + " " + f["name"]);
			program["flags"].append({
				"name" : f["name"],
				"offset" : f["offset"] - startAddr,
				"size" : f["size"]
			})
def saveComments(r,startAddr,endAddr):
	pinfo("Saving Comments");
	comments = r.cmdj("CCfj");
	program["comments"] = [];
	for c in comments:
		if c["offset"] >= startAddr and c["offset"] <= endAddr:
			pgood(hex(c["offset"]) + " " + c["name"]);
			program["comments"].append({
				"name" : c["name"],
				"type" : c["type"],
				"offset" : c["offset"] - startAddr
			})

def saveFunctions(r,startAddr,endAddr):
	pinfo("Saving Functions");
	functions = r.cmdj("aflj");
	for f in functions:
		if f["offset"] >= startAddr and f["offset"] <= endAddr:
			pgood(hex(f["offset"]) + " " + f["name"]);
			if not f["name"] in program["func"].keys():
				program["func"][f["name"]] = {
					"offset" : f["offset"] - startAddr,
					"vars": {}
				}
			else:
				program["func"][f["name"]]["offset"] = f["offset"] - startAddr;

def getRange(r,path):
	memory = (r.cmdj("dmj"));
	baseAddr = float("inf");
	endAddr = 0;
	for m in memory:
		if path == m["file"]:
			if baseAddr > m["addr"]:
				baseAddr = m["addr"];
			if endAddr < m["addr_end"]:
				endAddr = m["addr_end"];

	return [baseAddr,endAddr];


def pgrmFile(r): 
	info = (r.cmdj("ij"));
	myfile = info["core"]["file"];
	return myfile

def save(r):
	myfile = pgrmFile(r);
	program["path"] = myfile;

	baseAddr, endAddr = getRange(r,myfile);

	saveFunctions(r,baseAddr,endAddr);
	saveComments(r,baseAddr,endAddr);
	saveFlags(r,baseAddr,endAddr);
	
	saveDump(myfile);

def load(r,restore=True):
	myfile = pgrmFile(r);
	readDump(myfile);

	program["path"] = myfile;
	baseAddr, endAddr = getRange(r,myfile);
	if restore:
		restoreFunctions(r,baseAddr);
		restoreComments(r,baseAddr);
		restoreFlags(r,baseAddr);

def main():
	r = r2pipe.open();

	if len(sys.argv) == 2:
		if sys.argv[1] == "save":
			save(r);
		elif sys.argv[1] == "load":
			load(r,restore=True);
		elif sys.argv[1] == "help":
			perror("ToDo");
		else:
			perror("error");
	elif len(sys.argv) == 3:
		if sys.argv[1] == "func":
			if sys.argv[2] == "save":
				load(r,restore=False);
				saveLocalVars(r);
			elif sys.argv[2] == "load":
				load(r,restore=False);
				loadLocalVars(r);
			else:
				perror("error");
		else:
			perror("error");
	else:
		perror("error");

if __name__ == "__main__":
	main();
