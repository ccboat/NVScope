import json
import csv

import sys



res_path = sys.argv[1]
bof = res_path+'fffresult_bof.json'
cmdi = res_path+'fffresult_cmdi.json'

fbof = open(bof, 'r')
bof_res = json.load(fbof)
fbof.close()

fcmdi = open(cmdi, 'r')
cmdi_res = json.load(fcmdi)
fcmdi.close()

csvfile = open(res_path + 'output.csv', 'a+', newline='')
writer = csv.writer(csvfile)
writer.writerow(['BINNAME', 'TYPE', 'sink', 'addr', 'src', 'rank'])
csvfile.close()

#BOF
for bin in bof_res:
    if len(bof_res[bin]) > 0:
        for trace in bof_res[bin]:
            addr = trace['sink']['ins_addr']
            sink = trace['sink']['function']
            src = str(trace['sources_likely'])
            rank = trace['rank']
            binname = bin.split('squashfs-root/')[1].split('/overflow_results.json')[0]
            csvfile = open(res_path + 'output.csv', 'a+', newline='')
            writer = csv.writer(csvfile)
            writer.writerow([binname, 'BOF', sink, addr, src, rank])
            csvfile.close()

#CI
for bin in cmdi_res:
    if len(cmdi_res[bin]) > 0:
        for trace in cmdi_res[bin]:
            addr = trace['sink']['ins_addr']
            sink = trace['sink']['function']
            src = str(trace['sources_likely'])
            rank = trace['rank']
            binname = bin.split('squashfs-root/')[1].split('/cmdi_results.json')[0]
            csvfile = open(res_path + 'output.csv', 'a+', newline='')
            writer = csv.writer(csvfile)
            writer.writerow([binname, 'CI', sink, addr, src, rank])
            csvfile.close()

