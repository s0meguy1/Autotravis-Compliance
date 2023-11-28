# Autotravis-Compliance
This tool was created because clients wanted a better compliance report with specific fields, which was challenging with thousands of results. This was created to automate that process

What the tool does:
Sorts Nessus CSVs then places them into a formatted XLXS file:
This tool chews through a directory of csv compliance reports, sorts by unique items, groups IP's into one cell so you do not see multiple IP's with the same issue and does some trimming of other areas to make a nicer formatted report

## Usage
python3 AutotravisCompliance.py -d ./DIR-WITH-CSVs

The tool then outputs to one file, SAR.for.travis.compliance.xls

## Dependencies
pip install XlsxWriter
pip install pandas


## But why?
Our boss would get constantly changing requirements from the client, which would force us to spend hours re-analyzing the data and re-formatting. This makes it possible in seconds
