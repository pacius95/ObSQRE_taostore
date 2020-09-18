import attestation
from subtol_cli import *
import sys
import time

URL_BASE = 'http://127.0.0.1:49000'
SPID = 'FAA97D6CB2501FD5753E55F399AEF8A3'
ACK_STRING = b'trusted subtol enclave'

comm_txt = open('commands.txt', 'r')
commands = comm_txt.read().splitlines()
comm_txt.close()

i = 0

'''f = open("query","r")
pattern = f.read()
sys.stderr.write("%s \n" % pattern)
f.close()
'''
# for every ORAM
for comm in commands:
	
	seq = comm.split(',')
	
	# attestation context

	att = attestation.AttestationContext(SPID)
	att.init_session(URL_BASE)
	att.derive_SMK()
	att.send_msg2(URL_BASE)
	att.check_msg3(URL_BASE)
	att.remote_attestation(URL_BASE)
	att.derive_session_keys()
	att.final_handshake(URL_BASE, ACK_STRING)
	
	# create console
	subtol = SubtolCli(URL_BASE, att)
	
	# setup charset, oram and loading of file
	subtol.xc(seq[0])
	subtol.xc(seq[1])
	
	# poll
	code = subtol.qpoll()
	
	while code != 200:
		time.sleep(10)
		code = subtol.qpoll()
		
		
	# execute benchmark	
	if "ecoli" in comm:
		pattern = 'ATAèCCTGèèèCèèATACAèèTTA'
	elif "shake" in comm:
		pattern = 'haèèèndèèkerèèècèhèèièef'
	elif "sacc" in comm:
		pattern = 'ATACCATTCCAACCAACACACAGG'
	elif "chr21" in comm:
		pattern = 'ATACèèCAGGTèCAAAAACACCCA'
	elif "prot" in comm:
		pattern = 'CGèAHSRLDASAèèRèèLèAQLVD'
	elif "enron" in comm:
		pattern = 'Hèèèèèèeèèèèèlèèlèèèèèèo'
	else:
		sys.stderr.write('wrong benchmark')
		continue
			
	#queries = ["Fitch","business€trip","investment€portfolio"]#"Thank you very much"] € is used as a word separator	
	queries = [pattern]
	for pattern in queries:
		bench_str = 'benchmark ' + pattern + ' 32 0'
		subtol.xc(bench_str)
	
	sys.stdout.flush()
	
	# show progress
	i = i + 1
	
	perc = i / len(commands) * 100
	sys.stderr.write('%.2f%%\n' % perc)
	
	# close session
	subtol.xc('close')
