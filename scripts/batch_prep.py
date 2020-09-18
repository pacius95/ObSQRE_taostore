import os
import subprocess

sample_rate_dna = [8, 16, 32, 64, 128, 256, 512, 1024, 2048]
sample_rate_txt = [128, 256, 512, 1024, 2048]
sample_rate_pro = [32, 64, 128, 256, 512, 1024, 2048]

sample_rates = [("ecoli",sample_rate_dna), ("sacc",sample_rate_dna), ("chr21",sample_rate_dna), ("shake",sample_rate_txt), ("prot",sample_rate_pro)]

testcases_folder = 'bench'


DEVNULL = open(os.devnull, 'w')
mtest = dict()

def pow_to_str(power):
	if power >= 30:
		power = power - 30
		return str(2**power) + 'G'
	elif power >= 20:
		power = power - 20
		return str(2**power) + 'M'
	elif power >= 10:
		power = power - 10
		return str(2**power) + 'K'
	else:
		return str(2**power)

		
ptest = list()

for root, dirs, filenames in os.walk(testcases_folder):
	for files in filenames:
		fname = root + '/' + files
		fp = open(fname, 'r')
		fpstr = fp.read()
		flen = len(fpstr)
		
		chopsize = 20
		
		if flen < 2**26:
			ptest.append(fname)
		
		while 2**chopsize - 2 <= flen and chopsize <= 25:
			chopfname = root + '/' + pow_to_str(chopsize) + '_' + files
		
			fp2 = open(chopfname, 'w')
			fp2.write(fpstr[0 : 2**chopsize - 2])
			fp2.close()
			
			ptest.append(chopfname)
			chopsize = chopsize + 1
		
		fp.close()

# process sapsi
for files in ptest:
	outfile = files.replace('.txt', '.psi')
	
	print('PSI  => ' + outfile.split('.')[0])
	subprocess.call(['./prep', files, outfile, 'ciaone', '0', 'n'], stdout=DEVNULL, stderr=DEVNULL)

# process nbwt
for files in ptest:
	outfile = files.replace('.txt', '.nbwt')
	
	print('NBWT => ' + outfile.split('.')[0])
	subprocess.call(['./prep', files, outfile, 'ciaone', '1', 'n'], stdout=DEVNULL, stderr=DEVNULL)

# process vbwt
for files in ptest:
	
	rates = []
	
	for r in sample_rates:
		if r[0] in files:
			rates = r[1]
	
	for R in rates:
		outfile = files.replace('.txt', '_' + str(R) + '.vbwt')
		print('VBWT => ' + outfile.split('.')[0] + ' @' + str(R))
		subprocess.call(['./prep', files, outfile, 'ciaone', '2', 'n', str(R)], stdout=DEVNULL, stderr=DEVNULL)

