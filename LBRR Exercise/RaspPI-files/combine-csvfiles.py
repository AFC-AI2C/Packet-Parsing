#! /usr/bin/python3

#import os, glob
#import pandas as pd

### Import packages and set the working directory
#os.chdir("./csvs")

### Use glob to match the pattern ‘csv’
#extension = 'csv'
#all_filenames = [i for i in glob.glob('*.{}'.format(extension))]

### Use pandas to combine all files in the list
#combined_csv = pd.concat([pd.read_csv(f) for f in all_filenames ])

### Export to csv
#combined_csv.to_csv( "combined_csv.csv", index=False, encoding='utf-8-sig')

#=======================================================
#import pandas as pd

# reading two csv files
#data1 = pd.read_csv('./csvs/file.csv')
#data2 = pd.read_csv('datasets/borrower.csv')

# using merge function by setting how='inner'
#output1 = pd.merge(data1, data2,
#                   on='LOAN_NO',
#                   how='inner')

# displaying result
#print(output1)

import os
import pandas as pd
from pathlib import Path

### Variables
homeDir = str(Path.home())
csvDir  = homeDir + '/csvs/'

### Obtains and sorts the contents of the directory
listDir = sorted(os.listdir(csvDir))

### Creates a list of just the .pcap files
csvList = []
for file in listDir :
        if file.endswith('.csv') :
                csvList.append(csvDir + file)
#print(csvList)#
with open('/home/coeus/csvs/packet_00005_20220325141631.csv', 'r') as csv1:
	for line in csv1:
		print(line)

#for csv in csvList :
output1 = pd.merge(csvList,
    on='LOAN_NO',
    how='inner')

