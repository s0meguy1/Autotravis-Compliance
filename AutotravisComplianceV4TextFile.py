#!/usr/bin/python3
import xlsxwriter
import os
from os import system
import pandas as pd
import argparse
import re
from alive_progress import alive_bar
from alive_progress.styles import showtime, Show

# TODO:
#This version has a bug when database schema for column nessus_host_id is not unique, it will add those IP's as findings incorrectly
# Add Enclave/Plane option
# Add Finding added by option
def combine_csvs(dir_path, cms):
    if os.path.isfile('output.csv'):
        os.remove('output.csv')
    if os.path.isfile('output.txt'):
        os.remove('output.txt')
    # TODO: Maybe set "SC detected" here and new list if SC is detected, which would change cms...
    df = pd.DataFrame()
    file_csv_path = []
    file_txt_path = []
    for i, file_name in enumerate(os.listdir(dir_path)):
        if file_name.endswith('csv'):
            file_csv_path.append(os.path.join(dir_path, file_name))
    for i, file_name in enumerate(os.listdir(dir_path)):
        if file_name.endswith('txt'):
            file_txt_path.append(os.path.join(dir_path, file_name))

    #read in csv and txt file(s)
    if file_txt_path:
        print("Compliance File Path")
        df = pd.concat(map(pd.read_csv, file_csv_path))
        df.to_csv('output.csv', index=False)
        df_txt = pd.concat(map(pd.read_csv, file_txt_path))
        df_txt.to_csv('output.txt', index=False)
        get_compliance('output.csv',"output.txt", dir_path)
    else:
        print("Config File Path")
        print("Reading in: ", file_csv_path)
        df = pd.concat(map(pd.read_csv, file_csv_path))
        df.to_csv('output.csv', index=False)
        get_compliance_config_path('output.csv', dir_path)


     # get_compliance('output.csv',"output.txt", dir_path)
def parse_txt(file):
    file = open(file,'r')
    content = file.read()

    return content;

def compute(total, failedItems):
    df_cat = pd.DataFrame()

    with alive_bar(total) as bar:  # your expected total
        for index, row in failedItems.iterrows():
            category_string = str(row['Cross References']).split("CAT #",1)[1].split(",")[0]
            if(category_string == "I"):
                # row.at[index,'Severity']='HIGH'
                row.replace("High", 
               "HIGH", 
               inplace=True)
            elif(category_string == "II"):
                # row.at[,'Severity']='MEDIUM'
                row.replace("High", 
               "MEDIUM", 
               inplace=True)
                # row.loc[index,['Severity']] = 'MEDIUM'
            else:
                row.replace("High", 
               "LOW", 
               inplace=True)
            df_cat = df_cat._append(row, ignore_index=True)
            bar()  
    return df_cat

def compute_config_path(total, failedItems):
    df_cat = pd.DataFrame()

    with alive_bar(total) as bar:  # your expected total
        for index, row in failedItems.iterrows():
            try:
                category_string = str(row['Description']).split("CAT|",1)[1].split(",")[0]
            except:
                category_string = "NA"
            if(category_string == "I"):
                # row.at[index,'Severity']='HIGH'
                row.replace("FAILED", 
               "HIGH", 
               inplace=True)
            elif(category_string == "II"):
                # row.at[,'Severity']='MEDIUM'
                row.replace("FAILED", 
               "MEDIUM", 
               inplace=True)
                # row.loc[index,['Severity']] = 'MEDIUM'
            elif(category_string == "III"):
                row.replace("FAILED", 
               "LOW", 
               inplace=True)
            else:
                row.replace("FAILED", 
               "NA", 
               inplace=True)
            df_cat = df_cat._append(row, ignore_index=True)
            bar()  
    return df_cat
def get_compliance(file,file_txt, dir_path):
    # Create xlxs document:
    spreadsheetName = "SAR.for.complianceV2.xlsx"
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

    #Variables
    df_sorted = pd.DataFrame()
    columnHeaderFormatting = [
        ['A:A', 11, 'A1','IP(s)'],
        ['B:B', 15, 'B1', 'Source/PluginID'],
        ['C:C', 10, 'C1', 'Risk Level'],
        ['D:D', 45, 'D1', 'Finding Name'],
        ['E:E', 45, 'E1', 'Finding Details'],
        ['F:F', 45, 'F1', 'Recommendation'],
        ['G:G', 48, 'G1', 'Current Settings'],
        ['H:H', 5, 'H1', ''],
        ['I:I', 18, 'I1', 'Policy Requirements'], # remove this 
        ['J:J', 16, 'J1', 'STIG-ID'],
        ['K:K', 16, 'K1', 'STIG-Name' ],
        ['L:L', 45, 'L1', 'Nessus (Full Output)'],
        ['M:M', 19, 'M1', 'Comments'],
 
    ]

    # POAM ID was a wokey cell, made a specific setting for it:
    aCell = arialbold
    aCell.set_align('center')
    # Writing default items (POAM, IPs, etc):
    for index in range(len(columnHeaderFormatting)):
        worksheet.set_column(columnHeaderFormatting[index][0], columnHeaderFormatting[index][1], arialbold)
        worksheet.write(columnHeaderFormatting[index][2], columnHeaderFormatting[index][3], aCell)
    ########## pandas stuff - actual sorting: #########

    #read in data
    df = pd.read_csv(str(file))

    #read in plugin output into file
    plugin_output = parse_txt(file_txt)


    # This is set for Nessus Pro (FAILED), in SC its "High" instead of FAILED - need to add SC support
    failedItems = df[df['Severity'] == 'High']
    # failedItems['DescriptionGroup'] = failedItems['Cross References']#.str.extract(r'"(.*?)"')
    try:
        failedItems['IP Address'] = failedItems.groupby('Cross References')['IP Address'].transform(lambda x: ','.join(x.unique()))
    except:
        print(f"Failed to parse file: {str(file)}")

    failedItems = failedItems.drop_duplicates(subset='Plugin')


    #update severity field based on value
    df_cat=compute(len(failedItems), failedItems)

    #sort dataframe by severity 
    custom_dict = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    df_sorted = df_cat.sort_values(by=['Severity'], key=lambda x: x.map(custom_dict))
        


    testcount = 1
    with alive_bar(len(df_sorted)) as bar: 
        for index, row in df_sorted.iterrows():
        #################################
            # compute(len(df_sorted))
            
            testcount = testcount + 1
            betterdes = str(row['Cross References']).split('\n')[0]
            
            #seperate out data
            Vuln_ID_string = str(row['Cross References']).split("Vuln-ID #",1)[1].split(",")[0]
            plugin_description = str(plugin_output).split(str(row["Plugin"]),1)[1].split(str(Vuln_ID_string))[0] 
            Solution_Val_string = str(plugin_description).split("Solution:",1)[1].split("See Also:")[0]
            Actual_Val_string = str(plugin_description).split("Actual Value:",1)[1].split("Policy Value:")[0]
            Policy_Val_string = str(plugin_description).split("Policy Value:",1)[1].split("Solution")[0]
            Finding_Description_string = str(plugin_description).split(" - ",1)[1].split("Information:")[0] 
            STIG_ref_string = str(plugin_description).split("/zip/",1)[1].split(".zip")[0]
            Information_string = str(plugin_description).split("Information: ",1)[1].split("Result: ")[0]

            #hard code stig name
            STIG_Guideline = ""
            if "RHEL" in STIG_ref_string: 
                STIG_Guideline = "Red Hat Enterprise Linux 8 Security Technical Implmentation Guide"
            elif "Windows_10" in STIG_ref_string:
                STIG_Guideline = "Windows 10 Security Technical Implement Guide"
            
            elif "Windows_Sever_2019" in STIG_ref_string:
                STIG_Guideline = "Microsoft Windows Server 2019 Security Technical Implementation Guide"

                
            editedhosts = str(row['IP Address']).replace(',','\n')

            #write to Excel doc
            worksheet.write('A' + str(testcount), editedhosts, normaltext)
            worksheet.write('B' + str(testcount), "Nessus PluginID="+str(row['Plugin']), normaltext)
            worksheet.write('C' + str(testcount), str(row['Severity']), normaltext)
            worksheet.write('D' + str(testcount), Finding_Description_string, normaltext)
            worksheet.write('E' + str(testcount), Information_string,normaltext)
            worksheet.write_rich_string('F' + str(testcount), 
                normalBOLDtext, "Recommendation:\n", normaltext, Solution_Val_string, normalBOLDtext)
            worksheet.write_rich_string('G' + str(testcount),  
                normalBOLDtext, "'DISCLAIMER: This is an example output, please refer to Nessus Security Center for Actual Value information”\n", 
                normaltext, Actual_Val_string[:250] + "... Please refer to Nessus (Full Output) column.", normalBOLDtext)
            worksheet.write('H' + str(testcount), 5.14, blackcell)
            worksheet.write('I' + str(testcount), Policy_Val_string, normaltext )
            worksheet.write('J' + str(testcount), Vuln_ID_string, normaltext )
            worksheet.write_rich_string('K' + str(testcount), normalBOLDtext, 'STIG Policy Guideline: ', normaltext, STIG_Guideline,
                normalBOLDtext, '\nSTIG-USED: ', normaltext, STIG_ref_string, 
                normalBOLDtext)
            worksheet.write('L' + str(testcount), str(row['Plugin']) + plugin_description + "\n"+ row["Cross References"], normaltext )
            bar()
    workbook.close()

    print("Completed - XLSX Report ->", spreadsheetName)

def get_compliance_config_path(file, dir_path):
    # Create xlxs document:
    spreadsheetName = "SAR.for.compliance.BestPractive_CISCO_Firepower_Firewall.xlsx"
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

    #Variables
    df_sorted = pd.DataFrame()
    columnHeaderFormatting = [
        ['A:A', 11, 'A1','IP(s)'],
        ['B:B', 15, 'B1', 'Source/PluginID'],
        ['C:C', 10, 'C1', 'Risk Level'],
        ['D:D', 45, 'D1', 'Finding Name'],
        ['E:E', 45, 'E1', 'Finding Details'],
        ['F:F', 45, 'F1', 'Recommendation'],
        ['G:G', 48, 'G1', 'Current Settings'],
        ['H:H', 5, 'H1', ''],
        ['I:I', 22, 'I1', 'Policy Requirements'], # remove this 
        ['J:J', 16, 'J1', 'STIG-ID'],
        ['K:K', 18, 'K1', 'STIG-Name' ],
        ['L:L', 55, 'L1', 'Nessus (Full Output)'],
        ['M:M', 19, 'M1', 'Comments'],
 
    ]

    # POAM ID was a wokey cell, made a specific setting for it:
    aCell = arialbold
    aCell.set_align('center')
    # Writing default items (POAM, IPs, etc):
    for index in range(len(columnHeaderFormatting)):
        worksheet.set_column(columnHeaderFormatting[index][0], columnHeaderFormatting[index][1], arialbold)
        worksheet.write(columnHeaderFormatting[index][2], columnHeaderFormatting[index][3], aCell)
    ########## pandas stuff - actual sorting: #########

    #read in data
    df = pd.read_csv(str(file))

    # This is set for Nessus Pro (FAILED), in SC its "High" instead of FAILED - need to add SC support
    failedItems = df[df['Risk'] == 'FAILED']
    # failedItems['DescriptionGroup'] = failedItems['Cross References']#.str.extract(r'"(.*?)"')
    try:
        failedItems['Host'] = failedItems.groupby('Description')['Host'].transform(lambda x: ','.join(x.unique()))
    except:
        print(f"Failed to parse file: {str(file)}")

    failedItems = failedItems.drop_duplicates(subset='Description')


    #update severity field based on value
    df_cat=compute_config_path(len(failedItems), failedItems)

    #sort dataframe by severity 
    custom_dict = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'NA': 3}
    df_sorted = df_cat.sort_values(by=['Risk'], key=lambda x: x.map(custom_dict))
        


    testcount = 1
    with alive_bar(len(df_sorted)) as bar: 
        for index, row in df_sorted.iterrows():
        #################################
            # compute(len(df_sorted))
            
            testcount = testcount + 1
            betterdes = str(row['Description']).split('\n')[0]
            
            #seperate out data
            try:
                Vuln_ID_string = str(row['Description']).split("Vuln-ID|",1)[1].split("Policy")[0]

            except:
                Vuln_ID_string = "NA"

            try:
                plugin_description = str(row['Description']).split("[FAILED]\n\n",1)[1].split("Solution:")[0] 
            except:
                plugin_description = "NA"

            try:
                Solution_Val_string = str(row['Description']).split("Solution:",1)[1].split("See Also:")[0]
            except:
                Solution_Val_string = "NA"

            try:
                Actual_Val_string = str(row['Description']).split("Actual Value:",1)[1]
            except:
                Actual_Val_string = "NA"

            try:
                Policy_Val_string = str(row['Description']).split("Policy Value:\n",1)[1].split("\nActual Value:")[0]
            except:
                Policy_Val_string = "NA"
            
            try:
                Finding_Description_string = str(row['Description']).split("\"",1)[1].split("\" :")[0] 
            except:
                Finding_Description_string = "NA"

            try:
                STIG_ref_string = str(row['Description']).split("/zip/",1)[1].split(".zip")[0] 
            except:
                STIG_ref_string = "NA"            
            
        

            #hard code stig name
            STIG_Guideline = "NA"
            if "RHEL" in STIG_ref_string: 
                STIG_Guideline = "Red Hat Enterprise Linux 8 Security Technical Implmentation Guide"
            elif "Windows_10" in STIG_ref_string:
                STIG_Guideline = "Windows 10 Security Technical Implement Guide"
            
            elif "Windows_Sever_2019" in STIG_ref_string:
                STIG_Guideline = "Microsoft Windows Server 2019 Security Technical Implementation Guide"

                
            editedhosts = str(row['Host']).replace(',','\n')

            #write to Excel doc
            worksheet.write('A' + str(testcount), editedhosts, normaltext)
            worksheet.write('B' + str(testcount), "Nessus PluginID="+str(row['Plugin ID']), normaltext)
            worksheet.write('C' + str(testcount), str(row['Risk']), normaltext)
            worksheet.write('D' + str(testcount), Finding_Description_string, normaltext)
            worksheet.write('E' + str(testcount), plugin_description, normaltext)
            worksheet.write_rich_string('F' + str(testcount), 
                normalBOLDtext, "Recommendation:", normaltext, Solution_Val_string, normalBOLDtext)
            worksheet.write_rich_string('G' + str(testcount),  
                normalBOLDtext, "'DISCLAIMER: This is an example output, please refer to Nessus Security Center for Actual Value information”\n", 
                normaltext, Actual_Val_string[:250] + "... Please refer to Nessus (Full Output) column.", normalBOLDtext)
            worksheet.write('H' + str(testcount), 5.14, blackcell)
            worksheet.write('I' + str(testcount), Policy_Val_string, normaltext )
            worksheet.write('J' + str(testcount), Vuln_ID_string, normaltext )
            worksheet.write_rich_string('K' + str(testcount), normalBOLDtext, 'STIG Policy Guideline: ', normaltext, STIG_Guideline,
                normalBOLDtext, '\nSTIG-USED: ', normaltext, STIG_ref_string, 
                normalBOLDtext)
            worksheet.write('L' + str(testcount), str(row['Description']), normaltext )
            bar()
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

