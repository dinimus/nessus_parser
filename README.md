# Nessus report parser
Generating a Word (.docx) file from the .nessus file.

**Help:**
```
usage: nessus_parser.py [-h] [-i report.nessus] [-o output.docx] [-t template.docx]

Nessus report parser
optional arguments:
  -h, --help            show this help message and exit
  -i report.nessus, --input report.nessus
                        Input nessus file
  -o output.docx, --output output.docx
                        Output report file
  -t template.docx, --template template.docx
                        Template of report file

Example: ./nessus_parser.py -i report.nessus -o output.docx
```
### Nessus reports downloader
Change 'IP_of_NESSUS', 'YOUR_access_KEY' and 'YOUR_secret_KEY' in the nessus_reports_downloader.py.

Then just run it. All scan results will be downloaded from Nessus in .nessus format.
