import os
import subprocess

# sample_rate_dna = [64, 128, 256]
# sample_rate_dna = [512, 1024, 2048, 4096]
sample_rate_dna = [8192, 16384]


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


# ptest = ['1G_enron.txt']
ptest = ['4G_human.txt']

rates = sample_rate_dna

# process vbwt
for files in ptest:

        for R in rates:
                outfile = files.replace('.txt', '_' + str(R) + '.vbwt')
                print('VBWT => ' + outfile.split('.')[0] + ' @' + str(R))
                subprocess.call(['./prep', files, outfile, 'ciaone', '2', 'n', str(R)])#, stdout=DEVNULL, stderr=DEVNULL)
