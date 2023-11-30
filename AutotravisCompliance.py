#!/usr/bin/python3
import xlsxwriter
import os
from os import system
import pandas as pd
import argparse
import re

# TODO:
#This version has a bug when database schema for column nessus_host_id is not unique, it will add those IP's as findings incorrectly
# Add Enclave/Plane option
# Add Finding added by option
def combine_csvs(dir_path, cms):

    if os.path.isfile('output.csv'):
        os.remove('output.csv')
    # TODO: Maybe set "SC detected" here and new list if SC is detected, which would change cms...
    df = pd.DataFrame()
    file_path = []
    for i, file_name in enumerate(os.listdir(dir_path)):
        if file_name.endswith('csv'):
            file_path.append(os.path.join(dir_path, file_name))

    df = pd.concat(map(pd.read_csv, file_path))
    df_filtered = pd.DataFrame(df,
                         columns = cms)

    # df = pd.read_csv(file_path, dtype=str, usecols=cms)
    df.to_csv('output.csv', index=False)
    get_compliance('output.csv')

def get_compliance(file):
    # Create xlxs document:
    spreadsheetName = "SAR.for.travis.compliance.xlsx"
    spreadsheetloc = str(os.getcwd()) + "/" + spreadsheetName
    workbook = xlsxwriter.Workbook(spreadsheetloc)
    worksheet = workbook.add_worksheet()
    ### Create raw report template ###
    # Full black cells:
    blackcell = workbook.add_format()
    blackcell.set_pattern(1)
    blackcell.set_bg_color('black')
    # Used for first row:
    arialbold = workbook.add_format()
    arialbold.set_font_name('Calibri')
    arialbold.set_font_size(11)
    arialbold.set_bold(True)
    arialbold.set_align('bottom')
    arialbold.set_text_wrap()
    # Used for IP, Plugin, Risk, Details, etc:
    normaltext = workbook.add_format()
    normaltext.set_font_name('Calibri')
    normaltext.set_font_size(11)
    normaltext.set_bold(False)
    normaltext.set_align('top')
    normaltext.set_align('vleft')
    normaltext.set_text_wrap()
    # Used for "Certifier Comments:" and "Recommendation:":
    normalBOLDtext = workbook.add_format()
    normalBOLDtext.set_font_name('Calibri')
    normalBOLDtext.set_font_size(11)
    normalBOLDtext.set_bold(True)
    normalBOLDtext.set_align('top')
    normalBOLDtext.set_align('left')
    normalBOLDtext.set_text_wrap()
    # Sets specific heights of columns (first line below is for ROW 1):
    worksheet.set_column('A:A', 10.86, arialbold)
    worksheet.set_column('B:B', 12.14, arialbold)
    # POAM ID was a wokey cell, made a specific setting for it:
    aCell = arialbold
    aCell.set_align('center')
    # Writing default items (POAM, IPs, etc):
    worksheet.write('A1', 'POA&M ID', aCell)
    worksheet.write('B1', 'IP(s)', arialbold)
    worksheet.set_column('C:C', 10.86, arialbold)
    worksheet.write('C1', 'Source /PluginID', arialbold)
    worksheet.set_column('D:D', 10.86, arialbold)
    worksheet.set_column('E:E', 44.86, arialbold)
    worksheet.write('D1', 'Risk Level', arialbold)
    worksheet.write('E1', 'Finding Name', arialbold)
    worksheet.set_column('F:F', 32.43, arialbold)
    worksheet.write('F1', 'Finding Details', arialbold)
    worksheet.set_column('G:G', 48.29, normaltext)
    worksheet.write('G1', 'Certifier Comments & Recommendation', arialbold)
    worksheet.set_column('I:I', 10.86, arialbold)
    worksheet.write('I1', 'Enclave/Plane', arialbold)
    worksheet.set_column('J:J', 22.86, arialbold)
    worksheet.write('J1', 'Finding added by', arialbold)
    worksheet.set_column('K:K', 19.14, arialbold)
    worksheet.write('K1', 'Mitigated Onsite?', arialbold)
    # Black Cells
    worksheet.set_column('H:H', 5.14, arialbold)
    ########## pandas stuff - actual sorting: #########
    df = pd.read_csv(str(file))
    # This is set for Nessus Pro (FAILED), in SC its "High" instead of FAILED - need to add SC support
    failedItems = df[df['Risk'] == 'FAILED']
    failedItems['DescriptionGroup'] = failedItems['Description'].str.extract(r'"(.*?)"')
    try:
        failedItems['Host'] = failedItems.groupby('DescriptionGroup')['Host'].transform(lambda x: ','.join(x.unique()))
    except:
        print(f"Failed to parse file: {str(file)}")
    failedItems = failedItems.drop_duplicates(subset='DescriptionGroup')
    sorteditems = failedItems.sort_values('DescriptionGroup')
    testcount = 1
    for index, row in sorteditems.iterrows():
    #################################
        testcount = testcount + 1
        betterdes = row['Description'].split('\n')[0]
        try:
            betterdes2 = re.findall(r'"(.*?)"', betterdes)
        except:
            print(f"could not grep proper name from {betterdes}")
            betterdes2 = betterdes
        editedhosts = row['Host'].replace(',','\n')
        worksheet.write('B' + str(testcount), editedhosts, normaltext)
        worksheet.write('C' + str(testcount), "Nessus PluginID="+str(row['Plugin ID']), normaltext)
        worksheet.write('D' + str(testcount), str(row['Risk']), normaltext)
        for line in betterdes2:
            worksheet.write('E' + str(testcount), str(line)[:14], normaltext)
        try: 
            #removes duplicat host name and solution fields from description.
            evenBetterDescription = str(row['Description']).split("FAILED]\n\n",1)[1].split("Solution")[0]
            worksheet.write('F' + str(testcount), evenBetterDescription, normaltext)
    
        except: 
            worksheet.write('F' + str(testcount), str(row['Description']), normaltext)
        worksheet.write('G' + str(testcount), '', normaltext)
        worksheet.write_rich_string('G' + str(testcount), normalBOLDtext, 'Certifier Comments:', normaltext, "\nNone", normalBOLDtext, "\nRecommendation:\n", normaltext, str(row['Solution']))
        worksheet.write('A' + str(testcount), '', blackcell)
        worksheet.write('H' + str(testcount), 5.14, blackcell)
    workbook.close()
    print("Completed - XLSX Report ->", spreadsheetName)

parser = argparse.ArgumentParser(description='Autotravis for compliance using CSVs')
parser.add_argument('-d', '--dir', required=True, help='Please specify the directory with the csv files with -d')
args = parser.parse_args()
filepath = args.dir
### Only send columns you want to combine_csvs() - change if needed
### TODO: columns are set for Nessus Pro, not Security Center, SC has different names for most items below
columns = ['Plugin ID', 'Risk', 'Description', 'Solution', 'Name', 'Host']
combine_csvs(filepath, columns)

