# Autotravis-Compliance
This tool was created because clients wanted a better compliance report with specific fields, which was challenging with thousands of results. This was created to automate that process

What the tool does:
Sorts Tenable SC CSVs then places them into a formatted XLXS file:
This tool chews through a directory of csv compliance reports, sorts by unique items, groups IP's into one cell so you do not see multiple IP's with the same issue and does some trimming of other areas to make a nicer formatted report.

## Usage
python3 AutotravisCompliance.py -d ./DIR-WITH-CSVs

The tool then outputs to one file, SAR.for.travis.compliance.xls

## Dependencies
pip install XlsxWriter

pip install pandas

pip install alive-progress

## Wish List (Shortterm)
-Don’t auto fit Column L (too long)   (Both Vuln+Comp)

-Change column(M) header from "Comments" to "SSS Comments" (Both Vuln+Comp)

-Add new column (N) header as "INL Comments" (Both Vuln+Comp)

-autofilter for top row (Both Vuln+Comp)

-freeze top row (Both Vuln+Comp)

## Wish List (Longterm)
-change hardcoded output to dynamic DATE format. (Both Vuln+Comp)

-incorporate blacklist into autotravis compliance?
	New Column(N) with top row set to "DHS Requirements".   Set value to "Required" if no match.  And set value to "Optional - DHS Blacklist" if matches blacklist V-#####
 
-incorporate "last seen"  (Both Vuln+Comp)
   subtract first seen -> last seen   (bug, defender updates) (bug, IP’s differ)
   
-incorporate SSS & INL comments through a lookup  (Both Vuln+Comp)

-may be asked to move from github.com to TEN private GIT  (Both Vuln+Comp)

