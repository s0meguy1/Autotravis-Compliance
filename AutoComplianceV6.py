#!/usr/bin/python3
import xlsxwriter
import os
from os import system
import pandas as pd
import argparse
import re
from datetime import datetime
from alive_progress import alive_bar
from alive_progress.styles import showtime, Show


####################################
#COMPLIANCE PATH
#note the CSV containing plugin output needs to be in this order [Plugin, IP Address, Severity, plugin output] otherwise youll have an empty list
# then saved as a txt file 
#the CSV containing Cross Reference needs these columns [Plugin, IP Address, Severity, Cross References] 


####################################

cdt = datetime.now() # Get the local date and time

op = '%s_%s_%s' % (cdt.month, cdt.day, cdt.year)





#Global Variables
spreadsheetName = "Auto_Comp_black_list_" + op + ".xlsx"

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
format_gray = workbook.add_format({'bg_color': 'd8d8d8',
                                    'font_name': 'Calibri',
                                    'font_size': 11,
                                    'bold': True,
                                    'align': 'Center',
                                    'text_wrap': True })
format_grayer = workbook.add_format({'bg_color': 'E8e8e8',
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
    ['A:A', 10, 'A1','IP(s)'],
    ['B:B', 15, 'B1', 'Source/PluginID'],
    ['C:C', 12, 'C1', 'Risk Level'],
    ['D:D', 45, 'D1', 'Finding Name'],
    ['E:E', 45, 'E1', 'Finding Details'],
    ['F:F', 45, 'F1', 'Recommendation'],
    ['G:G', 48, 'G1', 'Current Settings'],
    ['H:H', 5, 'H1', ''],
    ['I:I', 25, 'I1', 'Policy Requirements'],
    ['J:J', 10, 'J1', 'STIG-ID'],
    ['K:K', 20, 'K1', 'STIG-Name' ],
    ['L:L', 16, 'L1', 'DHS Requirements'],
    ['M:M', 45, 'M1', 'Nessus (Full Output)'],
    ['N:N', 19, 'N1', 'SSS Comments'],
    ['O:O', 19, 'O1', 'INL Comments']
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
    if os.path.isfile('blacklist.csv'):
        os.remove('blacklist.csv')
    # TODO: Maybe set "SC detected" here and new list if SC is detected, which would change cms...
    df = pd.DataFrame()
    file_csv_path = []
    file_txt_path = []
    black_List = []
    bl_flag = 0
    for i, file_name in enumerate(os.listdir(dir_path)):
        if file_name.endswith('csv'):
            file_csv_path.append(os.path.join(dir_path, file_name))
    try: 
        #have your blacklist as a CSV in a directory "BlackList"
        for i, file_name in enumerate(os.listdir(dir_path+'/BlackList')):
            if file_name.endswith('csv'):
                black_List.append(os.path.join(str(dir_path+'/BlackList/'), file_name))
        bl_flag = 1
    except:
        print("No blackList")

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
            if(bl_flag):
                df_blacklist = pd.concat(map(pd.read_csv, black_List))
                df_blacklist.to_csv('blacklist.csv', index=True)
            else:
                df_blacklist = []
            get_compliance('output.csv',"output.txt",df_blacklist, dir_path, index, worksheets)
            if os.path.isfile('output.csv'):
                os.remove('output.csv')
            if os.path.isfile('output.txt'):
                os.remove('output.txt')
            if os.path.isfile('blacklist.csv'):
                os.remove('blacklist.csv')
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
            get_compliance_config_path('output.csv', dir_path, index, worksheets, item)
            if os.path.isfile('output.csv'):
                os.remove('output.csv')
            index += 1
        workbook.close()
     # get_compliance('output.csv',"output.txt", dir_path)
def parse_txt(file):
    file = open(file,'r')
    content = file.read()

    return content;
def parse_plugin_out(df, plugin_output):
    df_plugin_out = pd.DataFrame()
    search_string = []


    #seperate cross reference
    plugin_out = str(plugin_output).split(",,,,,,,,,,,,,,,,,,,,,,")


    #filter for failed only
    updated_plugin = [s for s in plugin_out if "Result: FAILED" in s]
    
    return updated_plugin
    # df_plugin_out.to_csv('output2.csv', mode='a', index=False, header=True)


def compute(total, failedItems_df):
    df_cat = pd.DataFrame()
    print("Processing CAT") 
    with alive_bar(total) as bar:  # your expected total
        for index, row in failedItems_df.iterrows():
            try:
                category_string = str(row['Cross References']).split("CAT #",1)[1].split(",")[0]
                if(category_string == "I"):
                # row.at[index,'Severity']='HIGH'
                    row.replace(row['Severity'], "HIGH (CAT I)", inplace=True)
                elif(category_string == "II"):
                    # row.at[,'Severity']='MEDIUM'
                    row.replace(row['Severity'], "MEDIUM (CAT II)", inplace=True)
                    # row.loc[index,['Severity']] = 'MEDIUM'
                else:
                    row.replace(row['Severity'], "LOW (CAT III)", inplace=True)
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
                    row.replace(row['Risk'], "HIGH (CAT I)", inplace=True)
                elif(category_string == "II"):
                    # row.at[,'Severity']='MEDIUM'
                    row.replace(row['Risk'], "MEDIUM (CAT II)", inplace=True)
                    # row.loc[index,['Severity']] = 'MEDIUM'
                else:
                    row.replace(row['Risk'], "LOW (CAT III)", inplace=True)
                df_cat = df_cat._append(row, ignore_index=True)
            except:
                row.replace(row['Risk'], "NA", inplace=True)
                df_cat = df_cat._append(row, ignore_index=True)

            bar()  
    return df_cat

def vulnerbility_config_path(total, failedItems):
    df_vul = pd.DataFrame()
    with alive_bar(total) as bar:  # your expected total
        for index, row in failedItems.iterrows():
            try:
                Vuln_ID_string = str(row['Description']).split("Vuln-ID|",1)[1].split("Policy")[0]
                row.replace(row['Core Impact'], Vuln_ID_string, inplace=True)
                df_vul = df_vul._append(row, ignore_index=True)

            except:
                df_vul = df_vul._append(row, ignore_index=True)

            bar()  
    return df_vul

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
            if index == len(columnHeaderFormatting)-1:
                worksheetList[j].set_column(columnHeaderFormatting[index][0], columnHeaderFormatting[index][1], format_grayer)
            else:
                worksheetList[j].set_column(columnHeaderFormatting[index][0], columnHeaderFormatting[index][1], format_gray)
            worksheetList[j].write(columnHeaderFormatting[index][2], columnHeaderFormatting[index][3], format_silver)
        j += 1
    return worksheetList

def worksheet_writer(worksheets, df_blacklist, file_index, row, testcount, plugin_output):
    testcount = testcount + 1
    blacklist_flag = False
    #seperate out data
    try:
        Vuln_ID_string = str(row['Cross References']).split("Vuln-ID #",1)[1].split(",")[0]
        if df_blacklist['Vuln ID'].eq(Vuln_ID_string).any():
            blacklist_flag = True
            
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
    if blacklist_flag:
        worksheets[file_index].write('L' + str(testcount), "Optional - DHS Blacklist", normaltext )
    else:
        worksheets[file_index].write('L' + str(testcount), "Required", normaltext )

    worksheets[file_index].write('M' + str(testcount), str(row['Plugin']) + plugin_description + "\n"+ row["Cross References"], normaltext )
    worksheets[file_index].autofilter('A1:O1')
    worksheets[file_index].freeze_panes(1,0)
    #autofit makes it look to long but is more readable uncomment to see after running
    #worksheets[file_index].autofit()

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
        if df_blacklist['Vuln ID'].eq(Vuln_ID_string).any():
            print("true: ", Vuln_ID_string)
            blacklist_flag = "True"
        else:
            print("False: ", Vuln_ID_string)
            blacklist_flag = "False"
    except:
        print("NA")
        blacklist_flag = "NA"
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
    if blacklist_flag == "True":
        worksheets[file_index].write('L' + str(testcount), "Optional - DHS Blacklist", normaltext )
    elif blacklist_flag == "NA":
        worksheets[file_index].write('L' + str(testcount), "NA", normaltext )
    else:
        worksheets[file_index].write('L' + str(testcount), "Required", normaltext )
    worksheets[file_index].write('M' + str(testcount), str(row['Description']), normaltext )
    worksheets[file_index].autofilter('A1:O1')
    worksheets[file_index].freeze_panes(1,0)
    return testcount

def get_failed_results(df, list_plugin_output):
    failed_items = pd.DataFrame()
    # df_plugin_out =pd.DataFrame()
    print("Proccessing Failed Results")
    with alive_bar(len(df)) as bar: 
        for index, row in df.iterrows():
            #note the CSV contoining plugin output needs to be in this order [plugin, ip addres, severity] otherwise youll have an empty list
            try:
                search_string =  str(str(row["Plugin"]) + "," + row["IP Address"] + "," + str(row["Severity"]) )
                for item in list_plugin_output:
                    if search_string in item: 
                        failed_items = failed_items._append(row, ignore_index=True)
            except:
                print("is your .txt file in the right order? [Plugin, IP, Severity]")
            bar()
    return failed_items
    
def get_compliance(file,file_txt, df_blacklist, dir_path, file_index, worksheets):
    #Variables
    df_sorted = pd.DataFrame()
    ########## pandas stuff - actual sorting: #########

    #read in data
    df = pd.read_csv(str(file))
    #read in plugin output into file
    plugin_output = parse_txt(file_txt)
    df_plugin_output = parse_plugin_out(df, plugin_output)
    #drop severity of type "info"
    df_noInfo = df[df.Severity != 'Info']


    #Grab failed results only
    failed_items = get_failed_results(df_noInfo, df_plugin_output)
    #join IP addresses
    try:
        failed_items['IP Address'] = failed_items.groupby('Cross References')['IP Address'].transform(lambda x: ','.join(x.unique()))
    except:
        print(f"Failed to parse file: {str(file)}")


    #Drop duplicate plugins
    df_combined_drop = failed_items.drop_duplicates(subset='Plugin')

    #Compute CAT
    failed_items=compute(len(df_combined_drop), df_combined_drop)
    # failed_items.to_csv('output2.csv', mode='a', index=False, header=True)


    #Filter out NA (SC will not have full infomration for result error)
    df_noNA = failed_items[failed_items.Severity != 'NA']


    #Sort DF
    custom_dict = {'HIGH (CAT I)': 0, 'MEDIUM (CAT II)': 1, 'LOW (CAT III)': 2}

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
            testcount = worksheet_writer(worksheets, df_blacklist, file_index, row, testcount, plugin_output)
            bar()
    
def get_compliance_config_path(file, dir_path, file_index, worksheets, item):

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

    


    #update severity field based on value
    df_cat=compute_config_path(len(failedItems), failedItems)
    if "Fire" not in item:
        df_vul=vulnerbility_config_path(len(failedItems), failedItems)
        df_vul = df_vul.drop_duplicates(subset='Core Impact')

        #sort dataframe by severity 
        custom_dict = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'NA': 3}
        df_sorted = df_vul.sort_values(by=['Risk'], key=lambda x: x.map(custom_dict))
    else:
        df_vul = failedItems.drop_duplicates(subset="Description")
        custom_dict = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'NA': 3}
        df_sorted = df_vul.sort_values(by=['Risk'], key=lambda x: x.map(custom_dict))        

    testcount = 1
    print("Writing to worksheets") 
    with alive_bar(len(df_sorted)) as bar: 
        for index, row in df_sorted.iterrows():
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

