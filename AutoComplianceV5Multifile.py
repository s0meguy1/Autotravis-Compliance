#!/usr/bin/python3
import xlsxwriter
import os
from os import system
import pandas as pd
import argparse
import re
from alive_progress import alive_bar
from alive_progress.styles import showtime, Show

#Global Variables
spreadsheetName = "test.xlsx"
# spreadsheetName = "Compliance_Windows_2010_Feb29_2024.xlsx"

spreadsheetloc = str(os.getcwd()) + "/" + spreadsheetName
workbook = xlsxwriter.Workbook(spreadsheetloc)


### Create raw report template ###

# Full black cells:
blackcell = workbook.add_format()
blackcell.set_pattern(1)
blackcell.set_bg_color('black')

format_silver = workbook.add_format({'bg_color': '#C0D0D0',
                                    'font_name': 'Calibri',
                                    'font_size': 11,
                                    'bold': True,
                                    'align': 'top',
                                    'text_wrap': True })
format_orange = workbook.add_format({'bg_color': 'orange',
                                    'font_name': 'Calibri',
                                    'font_size': 11,
                                    'bold': True,
                                    'align': 'top',
                                    'text_wrap': True })
format_yellow = workbook.add_format({'bg_color': 'yellow',
                                    'font_name': 'Calibri',
                                    'font_size': 11,
                                    'bold': True,
                                    'align': 'top',
                                    'text_wrap': True })
format_red = workbook.add_format({'bg_color': 'red',
                                    'font_name': 'Calibri',
                                    'font_size': 11,
                                    'bold': True,
                                    'align': 'top',
                                    'text_wrap': True })
#used for header row and comments column
format_gray = workbook.add_format({'bg_color': 'gray',
                                    'font_name': 'Calibri',
                                    'font_size': 11,
                                    'bold': True,
                                    'align': 'Center',
                                    'text_wrap': True })
arialbold = workbook.add_format({
                                    'font_name': 'Calibri',
                                    'font_size': 11,
                                    'bold': True,
                                    'align': 'top',
                                    'text_wrap': True })

# Used for IP, Plugin, Risk, Details, etc:
normaltext = workbook.add_format({
                                    'font_name': 'Calibri',
                                    'font_size': 11,
                                    'bold': False,
                                    'align': 'top',
                                    'text_wrap': True })
# Used for "Certifier Comments:" and "Recommendation:":
normalBOLDtext = workbook.add_format({
                                    'font_name': 'Calibri',
                                    'font_size': 11,
                                    'bold': True,
                                    'align': 'top',
                                    'text_wrap': True })

columnHeaderFormatting = [
    ['A:A', 11, 'A1','IP(s)'],
    ['B:B', 15, 'B1', 'Source/PluginID'],
    ['C:C', 9, 'C1', 'Risk Level'],
    ['D:D', 45, 'D1', 'Finding Name'],
    ['E:E', 45, 'E1', 'Finding Details'],
    ['F:F', 45, 'F1', 'Recommendation'],
    ['G:G', 48, 'G1', 'Current Settings'],
    ['H:H', 5, 'H1', ''],
    ['I:I', 18, 'I1', 'Policy Requirements'], # remove this 
    ['J:J', 12, 'J1', 'STIG-ID'],
    ['K:K', 20, 'K1', 'STIG-Name' ],
    ['L:L', 45, 'L1', 'Nessus (Full Output)'],
    ['M:M', 19, 'M1', 'Comments']
]
# TODO:
#This version has a bug when database schema for column nessus_host_id is not unique, it will add those IP's as findings incorrectly
# Add Enclave/Plane option
# Add Finding added by option
def combine_csvs(dir_path):
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
    
    if file_txt_path:
        index = 0
        worksheets = workbook_format(len(file_csv_path))
        print("Compliance File Path")

        for item in file_csv_path:
            df = pd.read_csv(item)
            df.to_csv('output.csv', index=True)
            df_txt = pd.concat(map(pd.read_csv, file_txt_path))
            df_txt.to_csv('output.txt', index=False)
            
            get_compliance('output.csv',"output.txt", dir_path, index, worksheets)
            if os.path.isfile('output.csv'):
                os.remove('output.csv')
            if os.path.isfile('output.txt'):
                os.remove('output.txt')
            index += 1

        workbook.close()
    else:
        print("Config File Path")
        index = 0
        worksheets = workbook_format(len(file_csv_path))

        for item in file_csv_path:
            print("-----Reading in: ", item)
            df = pd.read_csv(item)
            df.to_csv('output.csv', mode='a', index=False, header=True)
            get_compliance_config_path('output.csv', dir_path, index, worksheets)
            if os.path.isfile('output.csv'):
                os.remove('output.csv')
            index += 1
        workbook.close()
     # get_compliance('output.csv',"output.txt", dir_path)
def parse_txt(file):
    file = open(file,'r')
    content = file.read()

    return content;

def compute(total, failedItems_df):
    df_cat = pd.DataFrame()
    print("Processing CAT") 
    with alive_bar(total) as bar:  # your expected total
        for index, row in failedItems_df.iterrows():
            try:
                category_string = str(row['Cross References']).split("CAT #",1)[1].split(",")[0]
                if(category_string == "I"):
                # row.at[index,'Severity']='HIGH'
                    row.replace(row['Severity'], "HIGH", inplace=True)
                elif(category_string == "II"):
                    # row.at[,'Severity']='MEDIUM'
                    row.replace(row['Severity'], "MEDIUM", inplace=True)
                    # row.loc[index,['Severity']] = 'MEDIUM'
                else:
                    row.replace(row['Severity'], "LOW", inplace=True)
                df_cat = df_cat._append(row, ignore_index=True)
            except:
                row.replace(row['Severity'], "NA", inplace=True)
                df_cat = df_cat._append(row, ignore_index=True)

            bar()  
    return df_cat

def compute_config_path(total, failedItems):
    df_cat = pd.DataFrame()
    with alive_bar(total) as bar:  # your expected total
        for index, row in failedItems.iterrows():
            try:
                category_string = str(row['Cross References']).split("CAT|",1)[1].split(",")[0]
                if(category_string == "I"):
                # row.at[index,'Severity']='HIGH'
                    row.replace(row['Risk'], "HIGH", inplace=True)
                elif(category_string == "II"):
                    # row.at[,'Severity']='MEDIUM'
                    row.replace(row['Risk'], "MEDIUM", inplace=True)
                    # row.loc[index,['Severity']] = 'MEDIUM'
                else:
                    row.replace(row['Risk'], "LOW", inplace=True)
                df_cat = df_cat._append(row, ignore_index=True)
            except:
                row.replace(row['Risk'], "NA", inplace=True)
                df_cat = df_cat._append(row, ignore_index=True)

            bar()  
    return df_cat
    # df_cat = pd.DataFrame()
    # with alive_bar(total) as bar:  # your expected total
    #     for index, row in failedItems.iterrows():
    #         try:
    #             category_string = str(row['Description']).split("CAT|",1)[1].split(",")[0]
    #         except:
    #             category_string = "NA"
    #         if(category_string == "I"):
    #             # row.at[index,'Severity']='HIGH'
    #             row.replace("FAILED", 
    #            "HIGH", 
    #            inplace=True)
    #         elif(category_string == "II"):
    #             # row.at[,'Severity']='MEDIUM'
    #             row.replace("FAILED", 
    #            "MEDIUM", 
    #            inplace=True)
    #             # row.loc[index,['Severity']] = 'MEDIUM'
    #         elif(category_string == "III"):
    #             row.replace("FAILED", 
    #            "LOW", 
    #            inplace=True)
    #         else:
    #             row.replace("FAILED", 
    #            "NA", 
    #            inplace=True)
    #         df_cat = df_cat._append(row, ignore_index=True)
    #         bar()  
    # return df_cat

def workbook_format(file_list_length):
    # Create xlxs document:

    worksheetList = []
    index = 0
    while index < file_list_length:
        if(index == 0):
            worksheet = workbook.add_worksheet("sheet" + str(index))
            worksheetList.append(worksheet)
        if(index == 1):
            worksheet2 = workbook.add_worksheet("sheet" + str(index))
            worksheetList.append(worksheet2)
        if(index == 2):
            worksheet3 = workbook.add_worksheet("sheet" + str(index))
            worksheetList.append(worksheet3)
        if(index == 3):
            worksheet4 = workbook.add_worksheet("sheet" + str(index))
            worksheetList.append(worksheet4)
        if(index == 4):
            print("Error: this program only handles 4 files at a time.")
        index +=1
    
    #Variables
    df_sorted = pd.DataFrame()

    # POAM ID was a wokey cell, made a specific setting for it:
    aCell = arialbold
    aCell.set_align('center')
    # Writing default items (POAM, IPs, etc):
    j = 0

    while j < file_list_length:
        for index in range(len(columnHeaderFormatting)):
            worksheetList[j].set_column(columnHeaderFormatting[index][0], columnHeaderFormatting[index][1], format_gray)
            worksheetList[j].write(columnHeaderFormatting[index][2], columnHeaderFormatting[index][3], format_silver)
        j += 1
    return worksheetList

def worksheet_writer(worksheets, file_index, row, testcount, plugin_output):
    testcount = testcount + 1
    # betterdes = str(row['Cross References']).split('\n')[0]

    #seperate out data
    try:
        Vuln_ID_string = str(row['Cross References']).split("Vuln-ID #",1)[1].split(",")[0]

    except:
        Vuln_ID_string = "NA"
            
    try:
        plugin_description = str(plugin_output).split(str(row["Plugin"]),1)[1].split(str(Vuln_ID_string))[0] 
    except:
        plugin_description = "NA"

    try:
        Solution_Val_string = str(plugin_description).split("Solution:",1)[1].split("See Also:")[0]
    except:
        Solution_Val_string = "NA"

    try:
        Actual_Val_string = str(plugin_description).split("Actual Value:",1)[1].split("Policy Value:")[0]
    except:
        Actual_Val_string = "NA"

    try:
        Policy_Val_string = str(plugin_description).split("Policy Value:",1)[1].split("Solution")[0]
    except:
        Policy_Val_string = "NA"
    
    try:
        Finding_Description_string = str(plugin_description).split(" - ",1)[1].split("Information:")[0] 
    except:
        Finding_Description_string = "NA"

    try:
        STIG_ref_string = str(plugin_description).split("/zip/",1)[1].split(".zip")[0]
    except:
        STIG_ref_string = "NA"  

    try:
        Information_string = str(plugin_description).split("Information: ",1)[1].split("Result: ")[0]
    except:
        Information_string = "NA"  
    #hard code stig name
    STIG_Guideline = "NA"
    if "RHEL" in STIG_ref_string: 
        STIG_Guideline = "Red Hat Enterprise Linux 8 Security Technical Implmentation Guide"
    elif "Windows_10" in STIG_ref_string:
        STIG_Guideline = "Windows 10 Security Technical Implement Guide"
    elif "Windows_Server_2019" in STIG_ref_string:
        STIG_Guideline = "Microsoft Windows Server 2019 Security Technical Implementation Guide"
    editedhosts = str(row['IP Address']).replace(',','\n')


    worksheets[file_index].write('A' + str(testcount), editedhosts, normaltext)
    worksheets[file_index].write('B' + str(testcount), "Nessus PluginID="+str(row['Plugin']), normaltext)
    worksheets[file_index].write('C' + str(testcount), str(row['Severity']), normaltext)

    worksheets[file_index].write('D' + str(testcount), Finding_Description_string, normaltext)
    worksheets[file_index].write('E' + str(testcount), Information_string,normaltext)
    worksheets[file_index].write_rich_string('F' + str(testcount), 
        normalBOLDtext, "Recommendation:\n", normaltext, Solution_Val_string, normalBOLDtext)
    if len(Actual_Val_string) > 250:

        worksheets[file_index].write_rich_string('G' + str(testcount),  
        normaltext, Actual_Val_string[:250] + "... Please refer to Nessus (Full Output) column.", normalBOLDtext,
         "\n\n\n\n\n\nDISCLAIMER: This is an example output, please refer to Nessus Security Center for Actual Value information”\n", normalBOLDtext)
    else:
        worksheets[file_index].write_rich_string('G' + str(testcount),  
        normaltext, Actual_Val_string, normalBOLDtext,
         "\n\n\n\n\n\nDISCLAIMER: This is an example output, please refer to Nessus Security Center for Actual Value information”\n", normalBOLDtext)

    worksheets[file_index].write('H' + str(testcount), 5.14, blackcell)
    worksheets[file_index].write('I' + str(testcount), Policy_Val_string, normaltext )
    worksheets[file_index].write('J' + str(testcount), Vuln_ID_string, normaltext )
    worksheets[file_index].write_rich_string('K' + str(testcount), normalBOLDtext, 'STIG Policy Guideline: ', normaltext, STIG_Guideline,
        normalBOLDtext, '\nSTIG-USED: ', normaltext, STIG_ref_string, 
        normalBOLDtext)
    worksheets[file_index].write('L' + str(testcount), str(row['Plugin']) + plugin_description + "\n"+ row["Cross References"], normaltext )
    return testcount

def worksheet_writer_config_path(worksheets, file_index, row, testcount):
    testcount = testcount + 1
    # betterdes = str(row['Description']).split('\n')[0]

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
    worksheets[file_index].write('A' + str(testcount), editedhosts, normaltext)
    worksheets[file_index].write('B' + str(testcount), "Nessus PluginID="+str(row['Plugin ID']), normaltext)
    worksheets[file_index].write('C' + str(testcount), str(row['Risk']), normaltext)
    worksheets[file_index].write('D' + str(testcount), Finding_Description_string, normaltext)
    worksheets[file_index].write('E' + str(testcount), plugin_description, normaltext)
    worksheets[file_index].write_rich_string('F' + str(testcount), 
        normalBOLDtext, "Recommendation:", normaltext, Solution_Val_string, normalBOLDtext)
    worksheets[file_index].write_rich_string('G' + str(testcount),  
        normaltext, Actual_Val_string[:250] + "... Please refer to Nessus (Full Output) column.", normalBOLDtext,
         "\n\n\n\n\n\nDISCLAIMER: This is an example output, please refer to Nessus Security Center for Actual Value information”\n", normalBOLDtext)
    worksheets[file_index].write('H' + str(testcount), 5.14, blackcell)
    worksheets[file_index].write('I' + str(testcount), Policy_Val_string, normaltext )
    worksheets[file_index].write('J' + str(testcount), Vuln_ID_string, normaltext )
    worksheets[file_index].write_rich_string('K' + str(testcount), normalBOLDtext, 'STIG Policy Guideline: ', normaltext, STIG_Guideline,
        normalBOLDtext, '\nSTIG-USED: ', normaltext, STIG_ref_string, 
        normalBOLDtext)
    worksheets[file_index].write('L' + str(testcount), str(row['Description']), normaltext )
    return testcount

def get_failed_results(df, plugin_output):
    failed_items = pd.DataFrame()
    print("Proccessing Failed Results")
    with alive_bar(len(df)) as bar: 
        for index, row in df.iterrows():
            try:
                Vuln_ID_string = str(row['Cross References']).split("Vuln-ID #",1)[1].split(",")[0]

            except:
                Vuln_ID_string = "NA"

            try:
                search_string =  str(row["IP Address"] + "," + str(row["Plugin"]) + "," + str(row["Severity"]) )
                #plugin_description = str(plugin_output).split(str(row["Plugin"]),1)[1].split(str(Vuln_ID_string))[0] 
                plugin_description = str(plugin_output).split(search_string,1)[1].split(str(Vuln_ID_string))[0] 
            except:
                plugin_description = "NA"

            if "Result: FAILED" in plugin_description:
                
                failed_items = failed_items._append(row, ignore_index=True)
            bar()
    return failed_items

def get_compliance(file,file_txt, dir_path, file_index, worksheets):
    #Variables
    df_sorted = pd.DataFrame()
    ########## pandas stuff - actual sorting: #########

    #read in data
    df = pd.read_csv(str(file))

    #read in plugin output into file
    plugin_output = parse_txt(file_txt)

    #drop severity of type "info"
    df_noInfo = df[df.Severity != 'Info']
   
    #Grab failed results only
    failed_items = get_failed_results(df_noInfo, plugin_output)
    
    #join IP addresses
    try:
        failed_items['IP Address'] = failed_items.groupby('Cross References')['IP Address'].transform(lambda x: ','.join(x.unique()))
    except:
        print(f"Failed to parse file: {str(file)}")


    #Drop duplicate plugins
    df_combined_drop = failed_items.drop_duplicates(subset='Plugin')


    #Compute CAT
    failed_items=compute(len(df_combined_drop), df_combined_drop)
    failed_items.to_csv('output2.csv', mode='a', index=False, header=True)


    #Filter out NA (SC will not have full infomration for result error)
    df_noNA = failed_items[failed_items.Severity != 'NA']

    #Sort DF
    custom_dict = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    df_sorted = df_noNA.sort_values(by=['Severity'], key=lambda x: x.map(custom_dict))

    #used for debugging
    # df_sorted.to_csv('output3.csv', mode='a', index=False, header=True)
    # print("----------------------")
    # print(df_sorted)
    # print("----------------------")

    #output to worksheets
    testcount = 1  
    print("Writing to worksheets")  
    with alive_bar(len(df_sorted)) as bar: 
        for index, row in df_sorted.iterrows():

            #write to Excel doc
            testcount = worksheet_writer(worksheets, file_index, row, testcount, plugin_output)
            bar()
    
def get_compliance_config_path(file, dir_path, file_index, worksheets):

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
    print("Writing to worksheets") 
    with alive_bar(len(df_sorted)) as bar: 
        for index, row in df_sorted.iterrows():
        #################################
            testcount = worksheet_writer_config_path(worksheets, file_index, row, testcount)
            
            bar()
    

    print("Completed - XLSX Report ->", spreadsheetName)
parser = argparse.ArgumentParser(description='Autotravis for compliance using CSVs')
parser.add_argument('-d', '--dir', required=True, help='Please specify the directory with the csv files with -d')
args = parser.parse_args()
filepath = args.dir
### Only send columns you want to combine_csvs() - change if needed
# ### TODO: columns are set for Nessus Pro, not Security Center, SC has different names for most items below
columns = ['Plugin ID', 'Risk', 'Description', 'Solution', 'Name', 'Host']
combine_csvs(filepath)
print("Completed - XLSX Report ->", spreadsheetName)

