nessus-report
=============

Automatically parse and tabulate Nessus findings into OpenDocument tables

Example invocation (all platforms):
nessus-report  -s warn,hole -r high,medium -o h  *.nbe -o outputFile.odt

Example invocations (*nix):
nessus-report  -s warn,hole -r high,medium,moderate,low -o h  $( find . -iname "*.nbe*" ) -o outputFile.odt

This script relies on the ODFPy library.  It can be installed from the Python Package Index with the following command:
pip install http://pypi.python.org/packages/source/o/odfpy/odfpy-0.9.6.tar.gz. The Odf-py library is also available at http://opendocumentfellowship.com/projects/odfpy

Much thanks to Alessandro Di Pinto's Yet Another Nesuss Parser (YANP) examples for parsing .nessus XML files!
For more information, please see https://code.google.com/p/yet-another-nessus-parser/

Current issues as of (20130813):

  - ensure that 'critical' user input parameter is honored
  - add Compliance Finding results (for both .nessus and NBE)
  - fix CSV output
  - get header row to repeat across all pages of the table
  - make an automatic list for Finding# column
  - add file not found/no filename supplied exception handling
  - optimize for .nessus file loading speed.

Issues resolved:
  - fixed csv option handling bug - (20130813)
  - figure out which severities the NBE parser is excluding from matches [turns out it isn't; it's that NBE doesn't always list everything that the .nessus does    
  - fix NBE support  
  - fix broken constraint of searches by severity list and risk factor
  - ensure that column 6, CVE, appears in .ODT output
