#!/usr/bin/python2

# Nessus-Report:  Script to parse and tabulate Nessus findings.
# (c) 2012- Roey Katz, SeNet International.  
#
# Licensed under the terms of the GNU GPL, version 3.
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#                            
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Much thanks to Alessandro Di Pinto's Yet Another Nesuss Parser (YANP) examples for parsing .nessus XML files!
# For more information, please see https://code.google.com/p/yet-another-nessus-parser/

# Example invocations (*nix):
# nessus-report  -s warn,hole -r high,medium,moderate,low -o h  $( find . -iname "*.nbe*" ) -o outputFile.odt

# Example invocation (all platforms):
# nessus-report  -s warn,hole -r high,medium -o h  *.nbe -o outputFile.odt

# This script relies on the ODFPy library.
# It can be installed from the Python Package Index with the following command:
# pip install http://pypi.python.org/packages/source/o/odfpy/odfpy-0.9.6.tar.gz.    

# The Odf-py library is also available at http://opendocumentfellowship.com/projects/odfpy


#  Current issues as of (20130813):

#  - ensure that 'critical' user input parameter is honored
#  - add Compliance Finding results (for both .nessus and NBE)
#  - fix CSV output
#  - get header row to repeat across all pages of the table
#  - make an automatic list for Finding# column
#  - add file not found/no filename supplied exception handling
#  - optimize for .nessus file loading speed.

#  issues resolved:
#  - fixed csv option handling bug - (20130813)
#  - figure out which severities the NBE parser is excluding from matches [turns out it isn't; it's that NBE doesn't always list everything that the .nessus does    
#  - fix NBE support  

#  - fix broken constraint of searches by severity list and risk factor
#  - ensure that column 6, CVE, appears in .ODT output






USAGE = 'Flexible Nessusreport re-formatter.  Usage:  %prog [options] files'

import sys, re

# 20151120 - Fix encoding issue for nessus output files
# see http://stackoverflow.com/questions/21129020/how-to-fix-unicodedecodeerror-ascii-codec-cant-decode-byte
reload(sys)
sys.setdefaultencoding('utf8')

from optparse import OptionParser
from fnmatch import fnmatch
import string
import collections
from xml.dom.minidom import parse

from odf.opendocument import OpenDocumentText
from odf.style import Style, TextProperties, ParagraphProperties, TableColumnProperties
from odf.text import P as ODFParagraph
from odf.table import Table, TableColumn, TableRow, TableCell

import glob
   

options=None
counter=0
DEBUG=0


def uniq(s):
    return list(set(s))

def tryInt(i):
    if i.isdigit():  return int(i)
    else:  return i
    
def ipsort(iplist):
    return sorted(iplist, key=lambda ip:map(tryInt, ip.split('.')))


# Utility function to flatten a list recursively
def flatten(l):
    outList = []
    for i in l:
        if type(i)==list: outList = outList + flatten(i)
        else:
            outList.append(i)
    return outList


# print a result entry.  If you specify an _ipList, then it will be printed instead of result's ip
def  printEntryNormal( options, result, _ipList=[], count=1 ):

    if _ipList==[]: ipList=[result.getIP()]
    else: ipList = _ipList
    
    print '='*80
#    print 'Network:   %s' % result.network
    print 'IP:        %s' % ', '.join(ipsort(uniq(ipList)))
    print 'Service:   Port %s/%s (%s)' % (result.getPort(), result.getProtocol().upper(), result.getServiceName().upper())
    print 'Risk Factor: %s' % result.getRiskFactor()
    print 'Severity:  %s' % result.getSeverityAsWord()
    print 'ID:        %s' % result.getPluginID()
    print '-------------- Contents -----------------------------------------'
    for n in sorted(result.vuln.keys()):    print '%s:\n%s\n' % (n, result.vuln[n].strip())
    print '-----------------------------------------------------------------'

    
# Print an entry in comma-separated delimiter (CSV) format
def printEntryCSV( options, result, _ipList=[], count=None, delimiter=',' ):
    
#    SEPARATOR='|++|'
    
    if _ipList==[]: ipList=[result.getIP()]
    else: ipList = _ipList
    
    # print the header in this format:
    options.csvOutputFile.write( options.delimiter.join(
        [
        result.getPluginID() if _ipList is None else ",".join(ipsort(ipList)),
        result.getIP(),
        result.getPort(),
        result.getProtocol(),        
        result.getServiceName(),
        result.getSeverity(),
        result.getRiskFactor(),
        result.getDescription(),
        '\n'
        ]
        )
        )
        

        
class ODFTable:
    PWENC = "utf-8"
    
    def __init__(self, outputFilename, orderType='p'):
        self.outputFilename = outputFilename
        self.orderType = orderType
        self.table = None
        self.finding = 1
        
        self.initializeDocument()

    def initializeDocument( self ):
      
	self.textdoc = OpenDocumentText()
        
	# Create a style for the table content. One we can modify
	# later in the word processor.
	self.tablecontents = Style(name="Table Contents", family="paragraph")
	self.tablecontents.addElement(ParagraphProperties(numberlines="false", linenumber="0"))
	self.textdoc.styles.addElement(self.tablecontents)
        
        
        # ----------------- define a few styles --------------------
        
        # a Bold style
        self.BoldStyle = Style(name="Bold", family="paragraph")
        self.BoldProp = TextProperties(fontweight="bold")
        self.BoldStyle.addElement(self.BoldProp)
        self.textdoc.automaticstyles.addElement(self.BoldStyle)
        
        # for Critical findings
        self.CriticalStyle = Style(name="Critical Findings", family="paragraph")
        self.CriticalStyleProp = TextProperties(fontweight="bold", color="#FF0000")
        self.CriticalStyle.addElement(self.CriticalStyleProp)
        self.textdoc.automaticstyles.addElement(self.CriticalStyle)
        
        # for High findings
        self.HighStyle = Style(name="High Findings", family="paragraph")
        self.HighStyleProp = TextProperties(fontweight="bold", color="#FF2400")
        self.HighStyle.addElement(self.HighStyleProp)
        self.textdoc.automaticstyles.addElement(self.HighStyle)        
        
        # for Moderate findings
        self.ModerateStyle = Style(name="Moderate Findings", family="paragraph")
        self.ModerateStyleProp = TextProperties(fontweight="bold", color="#FF7F00")
        self.ModerateStyle.addElement(self.ModerateStyleProp)
        self.textdoc.automaticstyles.addElement(self.ModerateStyle)        
        
        # for Low findings
        self.LowStyle = Style(name="Low Findings", family="paragraph")
        self.LowStyleProp = TextProperties(fontweight="bold", color="#007FFF")
        self.LowStyle.addElement(self.LowStyleProp)
        self.textdoc.automaticstyles.addElement(self.LowStyle)        

        # for 'None' or 'Info' or 'Note' findings
        self.NoteStyle = Style(name="Note Findings", family="paragraph")
        self.NoteStyleProp = TextProperties(fontweight="bold")
        self.NoteStyle.addElement(self.NoteStyleProp)
        self.textdoc.automaticstyles.addElement(self.NoteStyle)                

        # nessus plugins can give widely inconsistent ratings: serious/high, medium/moderate, info/note/none...
        self.riskFactorsDict = {
           'critical':self.CriticalStyle,
           'high':self.HighStyle,
           'serious':self.HighStyle,
           'medium':self.ModerateStyle,
           'moderate':self.ModerateStyle,
           'low':self.LowStyle,
           'info':self.NoteStyle,
           'note':self.NoteStyle,
           'none':self.NoteStyle
           }
        
	# Create automatic styles for the column widths.
	# We want two different widths, one in inches, the other one in metric.
	# ODF Standard section 15.9.1
	widthshort = Style(name="Wshort", family="table-column")
	widthshort.addElement(TableColumnProperties(columnwidth="1.7cm"))
	self.textdoc.automaticstyles.addElement(widthshort)

	widthwide = Style(name="Wwide", family="table-column")
	widthwide.addElement(TableColumnProperties(columnwidth="1.5in"))
	self.textdoc.automaticstyles.addElement(widthwide)
        
        
        
        # hard-code columns styles, per column
	widthwide = Style(name="Wwide", family="table-column")
	widthwide.addElement(TableColumnProperties(columnwidth="1.5in"))
	self.textdoc.automaticstyles.addElement(widthwide)        
        

	# Start the table and describe the columns
	self.table = Table()
	if self.orderType=='p':
	    self.table.addElement(TableColumn(numbercolumnsrepeated=7,stylename=widthwide))

        # populate columns with headers...
        tr = TableRow()
        self.table.addElement(tr)
        
        # declare necessary vars
        tc1 = TableCell(); tc2 = TableCell(); tc3 = TableCell(); tc4 = TableCell(); tc5 = TableCell(); tc6 = TableCell(); tc7 = TableCell();
        addElem = lambda cell, text, s=self: cell.addElement(ODFParagraph(stylename=self.BoldStyle, text=unicode(text, ODFTable.PWENC)))


        # Add Column 1: Finding Number
        addElem(tc1, 'Finding Number')
        tr.addElement(tc1)
        
        # Add Column 2: Vulnerability Name
        addElem(tc2, 'Vulnerability Name')
        tr.addElement(tc2)
        
        # Add Column 3: NIST 800-53 Mapping
        addElem(tc3, '800-53 Mapping')
        tr.addElement(tc3)
        
        # Add Column 4: Description
        addElem(tc4, 'Description')
        tr.addElement(tc4)
        
        # Add Column 5: Recommendation
        addElem(tc5, 'Recommendation')
        tr.addElement(tc5)
        
        # Add Column 6: CVE
        addElem(tc6, 'CVE')
        tr.addElement(tc6)
        
        # Add Column 6: Hosts Affected
        addElem(tc7, 'IP Address (Sample of hosts effected)')
        tr.addElement(tc7)        

        
    # Print a single entry
    def printEntry( self, options, result, _ipList=[], count=1 ):

        if _ipList==[]: ipList=[result.getIP()]
        else: ipList = ipsort(_ipList)
    
        # print header

        tr = TableRow()
        self.table.addElement(tr)
        '''
        Finding Number
        Vulnerability Name
        800-53 Mapping
        Description
        Recommendation
        CVE
        IP Address (Sample of hosts effected)
        '''        


        tc1 = TableCell(); tc2 = TableCell(); tc3 = TableCell(); tc4 = TableCell(); tc5 = TableCell(); tc6 = TableCell(); tc7 = TableCell();
        addElem = lambda cell, text, s=self: cell.addElement(ODFParagraph(stylename=s.tablecontents, text=text.encode(ODFTable.PWENC)))
        
        
        riskFactor = result.getRiskFactor()

        # ---- Populate Column 1: Finding Number ----
        
        addElem(tc1, '') 
        addElem(tc1, str(count))
        tr.addElement(tc1)
        
        # increment the findings count (goes into first column)
        # self.finding+=1

        # ---- Populate Column 2: Vulnerability Description (prepended with port# and service name) ----
        
        #  grab the portnum
        portString='\n%s/%s (%s)' % (result.getPort(), result.getProtocol().upper(), result.getServiceName().upper())
        
        #  grab the first sentence of the synopsis (this forms a concise one-line description). 
        vulnerabilityString = unicode(result.getSynopsis().split('.',1)[0].replace('\\n', "\n") + '.')
        po = result.getPluginOutput()
        if po is not '':
            pluginOutput = '\n\nPlugin output:\n\n' + po
        else:
            pluginOutput = ''
        
        tc2.addElement( ODFParagraph(stylename=self.BoldStyle, text=(vulnerabilityString.decode("iso8859-8") + '\n' + portString).encode(ODFTable.PWENC)))
        tr.addElement(tc2)
        
        # ---- Populate Column 3:  NIST 800-53 Mapping ----
        tc3.addElement( ODFParagraph(stylename=self.BoldStyle, text=''.encode(ODFTable.PWENC)) )
        tr.addElement(tc3)

        # ---- Populate Column 4: Implication ----
        descString = ''.join(result.getDescription().replace('\\n', '\n')) # + pluginOutput.replace('\\n', '\n'))
        addElem(tc4, descString.strip() )
        tc4.addElement( ODFParagraph(stylename=self.BoldStyle, text="\n\n   RISK RATING:  ".encode(ODFTable.PWENC)))
        tc4.addElement( ODFParagraph(stylename=self.riskFactorsDict[riskFactor], text=riskFactor.encode(ODFTable.PWENC)))
        tr.addElement(tc4)
        
        # Populate  Column 5: Recomendation
        _recText = result.getRecommendation().replace('\\n', '\n')
        seeAlsoText = result.getSeeAlso().replace('\\n', '\n')
        solutionText = result.getSolution()
        if seeAlsoText is not '' or solutionText is not '':  
            recText = '\n'.join([_recText, '\n\n See also: ', seeAlsoText])
        else:
            recText = _recText
        addElem(tc5, recText)
        tr.addElement(tc5)
        
        # Column 6: CVE
        _cveText = result.getCVE()
        addElem(tc6, _cveText.encode("utf-8"))
        tr.addElement(tc6)

        # Populate Column 7: IP Address (Sample of hosts affected)
        addElem(tc7, '\n'.join(ipsort(uniq(ipList))))
        tr.addElement(tc7)

        
    def saveAndClose( self ):
        self.textdoc.text.addElement( self.table )
        self.textdoc.save(self.outputFilename)

        


# Holds exactly one test result
class Result:

    def __init__(self): 
        pass
    
    def getIP(self): return self.item_info['ip']

    def getContent(self): return self.vuln['content']
    def getServiceName(self): return self.vuln['service_name']
    def getSolution(self): return self.vuln['solution']
    def getSynopsis(self): return self.vuln['synopsis']
    def getDescription(self):  return self.vuln['description']
    def getRecommendation(self): return self.vuln['solution']
    def getAllContent(self): return '\n'.join(self.item_info.values()) + '\n'.join(self.vuln.values())
    def getPluginOutput(self): return self.vuln['plugin_output']
    def getPluginID(self): return self.vuln['plugin_id']
    def getCVE(self): return self.vuln['cve']
    def getSeeAlso(self): return self.vuln['see_also']
    def getRiskFactor(self):  return self.vuln['risk_factor']
    def getSeverity(self):    return self.vuln['severity']
    
    def getSeverityAsWord(self):
        return {'4':'CRITICAL Security Hole','0':"Open port",'1':"Informational",'2':"Security warning",'3':"Security hole"}[self.vuln['severity']]
    
    def getPort(self): return self.vuln['port']
    def getProtocol(self): return self.vuln['protocol']

    
class Parser:
    
    def __init__(self, _results = None):
        
      if _results is  None:
          self.results = ResultsBase()      
          
      else:
          self.results = _results

    def newQuery(self):  
      rq = ResultsBase( self.results[:] )
      return rq
   
    # user must implement this method
    def loadFile(self):
        pass
    
  
# parse a .NBE file    
class NBENessusParser(Parser):

    # implement loadFile
    def loadFile( self, fname ):
#        lines = [l.decode("utf-8") for l in open(fname).readlines()]
        lines  =  open(fname).readlines()


        # iterate over lines of the NBE input file
        for l in lines:
            
            
            # the last sixth content/description field can contain |'s, so we don't want to cut the rest of their results out.
            # Also, this is dumb.  String.split() allows "maxsplit" arguments but "".split() does not.
            _groups = string.split(l, '|', maxsplit=6)
          
            if _groups[0].strip() != 'results': continue
            
            groups = _groups[1:]
          
            counter = 0          

            # This used to be the unpacking line, but why should parsing Nessus .NBE files be straight-forward?
            
#           (solution, risk_factor, synopsis, see_also, description, plugin_output, bid, cve, other_references, note) = groups

            # unpack known knowns
            network = groups[0]
            ip = groups[1]
            service = groups[2]
               
            #  Continue unpacking.  Split() above should ideally yield six groups
            if len(groups)==6:
                pluginID = groups[3]
                severity = groups[4]
                content = groups[5]
                
            # ...unless it's a listing of an open port, in which csae it's just 3. 
            elif len(groups)==3:
                pluginID = "none"  # need to find out the name of this plugin.
                severity = "Info"
                content = ""
                
            # Otherwise, this is a totally weird line, and alert the user to bug the developer to fix it
            else: 
                print 'corner case detected: %s' % l
                print('len(groups) = %d' % len(groups))
                raise Exception("weird line, please alert developer")
            

            # debug
#            severities.append(severity)

            # holder for host information
            item_info = {
              'scan_start':   '',
              'scan_stop':    '',
              'os':           '',
              'hostname':     '',
              'netbios_name': '',
              'mac_address':  '',
              'ip':           ''
             }
           
            # holder for vulnerability information
            vuln = {
               'solution':    '',
               'risk_factor': '',
               'synopsis':    '',
               'see_also':    '',
               'description': '',
               'plugin_id':   '',
               'plugin_output': '',
               'bid':         '',
               'cve':         '',
               'other_references': '',
               'note':        '',
               'port':        '',
               'protocol':    '',
               'service_name':''
               }

            # parse plugin ID and severity
            item_info['ip'] = ip
            vuln['plugin_id'] = pluginID
            
            
            # Normalize Severity rating:  .NBE files use words, where .Nessus files use numbers; here we normalize this to a number.

            sevdict = {
#                            'Security Hole4':'4',   # <----- FIXME:  find what plugins that say "4" for Severity in .nessus file say in .NBE files and change the key accordingly
                            'Security Hole':'3',
                            'Security Warning':'2',
                            'Security Note':'1',
                            'Info':'0',
                            'Note':'0'
                            }
                            
            vuln['severity'] = sevdict[severity]
           
            # parse service, port and protocol
            if ' ' in service:
                vuln['service_name'],svc = service.split(' ')
                vuln['port'] = svc.split('/')[0][1:]
                vuln['protocol'] = svc.split('/')[1][:-1]
            
            else:
                if service[0] not in string.letters:
                
                    if DEBUG:
                        # um... we got a bad line.  Do nothing; this entry won't get reported (it's probably not a complete entry anyway)
                        print '!!!!!! bad line:'
                        print '  line=%s' % line
                        print '  network=%s, ip=%s, service=%s, pluginID=%s, severity=%s, content=%s ' % (network, ip, service, pluginID, severity, content)

                    vuln['port'] = 'general' # _service.split('/')[1]
                    vuln['protocol'] = 'general'
                    vuln['service_name'] = 'general' # _service
            

            # try to break down the description.  This sucks, because the NASL output isn't consistent across Nessus' 10,000+ plugins.
            info = self._parseDescription(content.strip().replace('\\n','\n'), defaultToken='description')

            # only return the first word of the Risk Rating.  It could be "Low", but it also could be
            # "Low / CVSS Base Score : 2  (AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)".
            # Nessus plugin output is insconsistent.
            vuln['risk_factor']  = info['risk factor'].split()[0].lower()
            vuln['solution'] = info['solution']
            vuln['synopsis'] = info['synopsis']
            vuln['see_also'] = info['see also'] # differs.
            vuln['description'] = info['description']
            vuln['plugin_otput'] = info['plugin output']
            vuln['bid'] = info['bid']
            vuln['cve'] = info['cve']
            vuln['other_references'] = info['other references']
            vuln['note'] = info['note']
            
            # add item to database
            newResult = Result()
            newResult.vuln = vuln
            newResult.item_info = item_info

            self.results.addResult(newResult)
            

            
        
    # parse nessus plugin output results
    def _parseDescription( self, _text,  defaultToken ):
        
             keywords = ['solution', 'risk factor', 'synopsis', 'see also', 'description', 'see_also', 'plugin output', 'bid', 'cve', 'other references', 'note']
        
             # set up parsed results dictionary        
             info = { n:"" for n in keywords+[defaultToken] }

             # catch any text that is not given a field name (due to inconsistent Nessus plugin output--
             # Some plugins label it "description", some give no label, so we catch it here)
             currentField = defaultToken
             text = _text.replace('\\n',' ').strip()

             for line in text.splitlines():
          
               # separate line into "firstWord" (candidate field name) and the rest of the line
               # example:  "Risk Factor: High" vs. "plugin output : littered with :  many : stray : colons"
               if ':' in line:
            
                   firstWord, rest = map(str.strip, line.split(':', 1))
                   firstWord = firstWord.strip().lower()

                   # if this first word matches a keyword, then this is a field name.  
                   # Fill its corresponding field in 'info' with the rest of the line
                   if firstWord in keywords:
                       currentField = firstWord
                       info[currentField] = rest
            
                   # if this is a false positive (had a ':' but was not a keyword), then treat it as a 
                   # continuation of the previous line and just append it.
                   else:
                       info[currentField] += line.replace('\n', ' ') + ' '
            
               # if this is not a keyword (no ':' present at all), 
               else:
                   info[currentField] += line.replace('\n', ' ') + ' '   # get rid of stupid Nessus newlines

        
             # clean up the values
             for n in info.keys(): info[n] = info[n].strip()
      
             # corner case:  early Nessus plugins didn't output Risk Factor if the output was just 
             # informational (i.e. "this is the remote server's banner output").  So set it to "None".
             if info['risk factor'] is '': info['risk factor'] = 'None'          
          
             return info


  


    
# parse .nessus version 2 files.  These are XML.  Now we're talking.
class DotNessusParser(Parser):

    # Load and parse a .nessus file and add all Nessus scan result entries to the databaes
    # Follows code sampled from Alessandro Di Pinto's Yet Another Nessus Parser (YANP) project,
    # available at https://code.google.com/p/yet-another-nessus-parser/
    # Thanks Alessandro!
    def loadFile( self, fname ):
        
       # Automatic parse of .nessus file
       dom = parse(fname)
                        
       # For each host in report file, it extracts information
       for host in dom.getElementsByTagName('ReportHost'):
           
          # Get IP address
          _ip = host.getAttribute('name')
          if _ip == "":
              continue # Error getting IP address, skip!
          else:
              ip = _ip
               
          # Parse information out of individual node     
          for item in host.childNodes:              
                  
               if item.nodeName == 'HostProperties':
                   item_info = {
                   'scan_start':   '',
                   'scan_stop':    '',
                   'os':           '',
                   'hostname':     '',
                   'netbios_name': '',
                   'mac_address':  '',
                   'ip':           '',
                   }
                   
                   for properties in item.childNodes:
                   
                      if properties.attributes is None: continue

                      # debug, RK 
                      item_info['ip'] = ip
                  
                      # Extract generic information
                      if  properties.getAttribute('name') == 'HOST_START':
                          item_info['scan_start'] = properties.childNodes[0].nodeValue
                                                                                                     
                      if properties.getAttribute('name') == 'HOST_END':
                          item_info['scan_stop'] = properties.childNodes[0].nodeValue
                                                                                                                                                             
                      if properties.getAttribute('name') == 'operating-system':
                          item_info['os'] = properties.childNodes[0].nodeValue
                                                                                                                                                                                                                     
                      if properties.getAttribute('name') == 'host-fqdn':
                          item_info['hostname'] = properties.childNodes[0].nodeValue
                                                                                                                                                                                                                                                                             
                      if properties.getAttribute('name') == 'netbios-name':
                          item_info['netbios_name'] = properties.childNodes[0].nodeValue
                                                                                                                                                                                                                                                                                                                                     
                      if properties.getAttribute('name') == 'mac-address':
                          item_info['mac_address'] = properties.childNodes[0].nodeValue


               # Information extraction
               if item.nodeName == 'ReportItem':
                   if item.attributes is None: continue
                 
                   # Skip specific vulnerability if it is into a blacklist
#                   if item.getAttribute('pluginID') in self._blacklist:
#                      self._blacklist_hit += 1
#                      continue
                 
                   vuln = {
                       'plugin_name':       '',
                       'plugin_id':         '',
                       'plugin_type':       '',
                       'plugin_output':     '',
                       'port':              '',
                       'protocol':          '',
                       'description':       '',
                       'solution':          '',
                       'service_name':      '',
                       'cvss_base_score':   '0.0',
                       'cvss_vector':       '',
                       'exploit_available': '',
                       'metasploit':        '',
                       'cve':               '',
                       'risk_factor':       '',
                       'see_also':          '',
                       'bid':               '',
                       'other_references':  '',
                       'severity':          '',
                       'synopsis':          ''
                       }

                   # Extract generic vulnerability information
                   vuln['plugin_name'] = item.getAttribute('pluginName')
                   vuln['plugin_id'] = item.getAttribute('pluginID')
                   vuln['port'] = item.getAttribute('port')
                   vuln['protocol'] = item.getAttribute('protocol')
                   vuln['description'] = item.getAttribute('description')
                   vuln['service_name'] = item.getAttribute('svc_name')
                   
                   # This is also processed before returning
                   vuln['risk_factor'] = item.getAttribute('risk_factor')
                 
                   vuln['see_also'] = item.getAttribute('see_also')
                   vuln['severity'] = item.getAttribute('severity')
                   vuln['other_references'] = item.getAttribute('other_references')
                   vuln['bid'] = item.getAttribute('bid')
                   vuln['synopsis'] = item.getAttribute('synopsis')

                   # No another information about vulnerability, continue!
                   if len(item.childNodes) == 0: continue
                 
                   # Extract detailed vulnerability information
                   for details in item.childNodes:
                       if details.nodeName == 'description':
                           vuln['description'] = details.childNodes[0].nodeValue
                         
                       if details.nodeName == 'solution':
                           vuln['solution'] = details.childNodes[0].nodeValue

                       if details.nodeName == 'plugin_type':
                           vuln['plugin_type'] = details.childNodes[0].nodeValue
                           
                       if details.nodeName == 'plugin_output':
                           vuln['plugin_output'] = details.childNodes[0].nodeValue                           
                         
                       if details.nodeName == 'cvss_base_score':
                           vuln['cvss_base_score'] = details.childNodes[0].nodeValue
                         
                       if details.nodeName == 'cvss_vector':
                           vuln['cvss_vector'] = details.childNodes[0].nodeValue

                       if details.nodeName == 'exploitability_ease' or details.nodeName == 'exploit_available':
                           if details.childNodes[0].nodeValue.find('true') >= 0 or details.childNodes[0].nodeValue.find('Exploits are available') >= 0:
                               vuln['exploit_available'] = 'true'
                           else:
                               vuln['exploit_available'] = 'false'

                       if details.nodeName == 'exploit_framework_metasploit':
                           if details.childNodes[0].nodeValue.find('true') >= 0:
                               vuln['metasploit'] = 'true'
                               vuln['exploit_available'] = 'true'
                           else:
                               vuln['metasploit'] = 'false'
                               
                       if details.nodeName == 'risk_factor':
                           vuln['risk_factor'] = details.childNodes[0].nodeValue.lower()  # RK 20130712: Normalize this to lower-case
                         
                       if details.nodeName == 'cve':
                           vuln['cve'] = details.childNodes[0].nodeValue
                           
                       if details.nodeName == 'synopsis':
                           vuln['synopsis'] = details.childNodes[0].nodeValue
                           
                       if details.nodeName == 'see_also':
                           vuln['see_also'] = details.childNodes[0].nodeValue

                       if details.nodeName == 'severity':
                           vuln['severity'] = details.childNodes[0].nodeValue

                       if details.nodeName == 'bid':
                           vuln['bid'] = details.childNodes[0].nodeValue
                           
                       if details.nodeName == 'other_references':
                           vuln['other_references'] = details.childNodes[0].nodeValue
                        
                       # 20140325 Roey Katz: Some plugins report Risk Rating of 0 yet mention "Critical: 1" in their output.  This is a corner case. 
#                       try:
#                           if vuln['plugin_output'].find("Critical: 1") > 0 or vuln['risk_factor']=="critical":
#                               vuln['risk_factor'] = "critical"

#                               print "FOUND CRITICAL on ip=%s, pluginid=%s, output=%s" % (item_info['ip'], vuln['pluginid'], vuln['plugin_output'])

#                       except KeyError: # plugin_output and/or risk_factor might not be defined for the row we're processing
#                           pass
                           
                   # create a new database record
                   newResult = Result()
                   
                   # attach the host info that we collected way above                   
                   newResult.item_info = item_info                    
                   
                   # attach the vulnerability info that we collected above
                   newResult.vuln = vuln  
           
                   # Store information extracted into a new row in the database
                   self.results.addResult(newResult)
                   

    

# for querying the results    
class ResultsBase:

    def __init__( self ):
      
#      self.results = set(_results)  # is line needed, or is there a better way to cut out duplicate entries?
      self.results = []
      self.count = len(self.results)

    def size(self):
        return len(self.results) # self.count only gets updated once matches are run via _commitMatch()
    
    # add a Result instance to the database
    def addResult(self, res):
        self.results.append(res)

    # narrow database results based on a condition function that returns True or False given a Result object
    def _commitMatch( self, cond ):
        
        _results = []
        
        # long form: clear
        for r in self.results:

            if cond(r):
              _results.append(r)
              
        # short form: not as clear
#       self.results = self.results & set(r for r in self.results if cond(r))

        self.results = _results        
        self.count = len(self.results)


    def matchHost( self, ipList ):  self._commitMatch( lambda r: r.getIP() in ipList )
    def matchPort( self, portList ):  self._commitMatch( lambda r: r.getPort() in portList )
    def matchContent( self, querystring ):  self._commitMatch( lambda r: fnmatch(querystring, r.getAllContent()) )
    def matchPluginIDList( self, pluginIDList ): self._commitMatch( lambda r:r.getPluginID() in pluginIDList)
    def matchContentRegexp( self, querystring ):  
      m = re.compile(querystring, re.DOTALL); 
      self._commitMatch( lambda r: m.match(r.getAllContent()) )
      
    def matchSeverity( self, severityList ):
        # Short form
        # self._commitMatch( lambda r: r.getSeverity() in severityList ) # severity )
        
        # Longer form is easier to read
        def cond(r):
            if r.getSeverity() in severityList:
                return True
            
            return False
        
        self._commitMatch( cond )


    def matchRiskFactors( self, riskFactorsList ):
        # One-liner form:
        # self._commitMatch( lambda r: r.getRiskFactor() in riskFactorsList ) # self.riskfactors )

        # But this longer form is easier to read
        def cond(r):
            if r.getRiskFactor() in riskFactorsList:
                return True
            return False
         
        self._commitMatch( cond )

    
    def getCount(self): return len(self.results)
    def getAll(self): return self.results

    # yield a tuple of (host, vulnerabilitylist) where 'host' is the hostname as a string and 'vulnerabilitylist' is a list of results representing that host's vulnerabilities
    def getHosts( self ):   return self.getOrderedQuery( Result.getIP )
    def getHostsByPort( self ): return self.getOrderedQuery( Result.getServicePort)
    
       
    # yield a tuple of (host, vulnerabilitylist)
    def getVulnsByHost( self ):  
        
        # 1. construct dictionary with hosts as keys and lists of vulnerabilities as values
        # I bet this whole function can be compressed into one line with python 3.x dict comprehensions....
        
        hostvulns = {}
        for v in self.getAll(): # getVulnerabilities():
            
            #********insert severity sorting magic here******
            
            ip = v.getIP()
            
            if not hostvulns.has_key(ip):
                hostvulns[ip] = [v]  # note: getOrderedDict() returns [(ip,vulnerability),...]
            else: 
                hostvulns[ip].append(v)
            
        # 2. for every host, return a vulnerability
        for host in ipsort(hostvulns.keys()):
            for vuln in hostvulns[host]:
               yield(vuln)
    
    # return a tuple of (vulnerability, hostlist) where
    # 'vulnerability' is the result and 'hostlist' a list of hostnames
    # as strings representing the hosts harboring this vulnerability
    def getVulnerabilities( self ):
        return self.getOrderedQuery( Result.getPluginID, orderByPort=True )        

    # get vulnerabilities by CVE
    def getHostsByCVE( self ): return self.getOrderedQuery( Result.getCVE, orderByPort=True )

    # generate a list of our results, ordered by a 'selector' function
    # that accepts a Result and returns a sort key based on it
    def getOrderedQuery( self, selector, orderByPort=False, orderByHost=False ):
      queryDict = {}
      
      
      for x in self.results:
          
        if not queryDict.has_key(selector(x)):  queryDict[selector(x)] = [x]  # cubbyhole the results
        else: queryDict[selector(x)].append(x)
        
      order = queryDict.keys()
      if orderByPort:
          
          order = sorted(queryDict.keys(), key=lambda k: tryInt(queryDict[k][0].getPort()))
        
      if orderByHost:
        order = ipsort( queryDict.keys() )
    
      sortedOrder = order
        
      # sort by Risk Factor
      sortedOrderDict = collections.OrderedDict()
      for n in ('Critical','High', 'Serious', 'Medium','Moderate','Low','Info','None', ''): sortedOrderDict[n] = []
      
      if orderByPort:
          
        for j in order:

            r = queryDict[j][0].getRiskFactor()
            sortedOrderDict[r.title()].append(j)

        # flatten dictionary and store it into the sortedOrder list
        sortedOrder = [item for sublist in sortedOrderDict.values() for item in sublist]

      # feed results back to the caller successively
      for k in sortedOrder:
        yield (k, queryDict[k])
        

        
# Parse command-line arguments        
def parseArgs( argv ):
    """parseArgs(list of args) -> (dictionary of values, list leftover arguments)

       Takes a list of parameters (such as sys.argv) and returns a tuple containing a dictionary of keyword arguments and a list of non-keyword arguments.
    """

    parser = OptionParser()
    parser.add_option("-o", "--order", type="choice", action="store", choices=["p","h","g","c"], default="p", dest="orderType",
              help="specify a display sorted by (p)lugin, (c)ve id, (h)ost, or just (g)enerate a hostfile")
    parser.add_option("-f", "--odf", type="string", action="store", dest="odfOutputFilename",
              help="output to this file in ODF format", default="")
    parser.add_option("-p", "--portlist", type="string",  action="store", dest="portList",
              help="specify specific ports to show")
    parser.add_option("-r", "--riskfactors", type="string", action="store", dest="riskFactorsList", default="critical,high,moderate,medium,low,none",
              help="specify list of allowable risk factors (default is any of critical,high,moderate,medium,low,none")
    parser.add_option("-t", "--hostlist", type="string",  action="store", dest="hostList",
              help="specify specific hosts to show")
    parser.add_option("-s", "--severities", type="string", action="store", dest="severityList", default="critical_hole,hole,warn,note,info,openport",
              help="specify specific list of severity codes to show (default is any of critical_hole,hole,warn,note,info,openport")
    parser.add_option("-q", "--query", type="string", action="store", dest="contentQuery",
              help="show all results whose synopses match this regular expression")
    parser.add_option("-i", "--idlist", type="string", action="store", dest="pluginIDList",
              help="display only results that match these Nessus plugin IDs")
    parser.add_option("-c", "--csv", type="string", action="store", dest="csvOutputFilename", default="",
              help='output CSV-friendly text delimitted by default or overriden delimiter to a given filename (use "0" for standard output)')
#    parser.add_option("-c", "--csv", action="store_true", dest="CSV", default=False,
#              help="output CSV-friendly text delimitted by |++| (overridable with the 'd' option)")
    parser.add_option("-d", "--delimiter", type="string", action="store", dest="delimiter", default="|++|", 
              help="override CSV delimiter default of |++|")

    (options, args) = parser.parse_args()              
              
    if options.orderType: options.orderType = options.orderType.lower()

    return (options,args)

# Utility function to parse a range from a string
def getRange( rangestring ):
    if '-' in rangestring:
      start,end = rangestring.split('-')
      intrange = [str(s) for s in range(int(start),int(end)+1)]
    else:
      intrange = [rangestring]
    
    return intrange

# Utility function to parse a list of plugins
def parsePluginIDList( pluginIDList ):
    groups = pluginIDList.split(',')
    return groups


# Utility function to parse a list of ports
def parsePortList( portstring ):
    groups = portstring.split(',')

    # cases:
    # a-b
    # a,b
    
    portList = []
    
    for i in groups:
      if '-' in i:
        start,end = i.split('-')
        portRange = [str(s) for s in range(int(start),int(end)+1)]
        portList += portRange
      else:
        portList.append(i)
        
    return uniq(portList) # get rid of repeats


# Utility function parse a list of hosts   
def parseHostList( ipstring ):
    """parseIPList() -> [list of strings]
       take a string containing a comma-separated list of IPs specified as either ranges or individual IPs and networks.
       Returns a list of applicable IPs. 
    """

    # ideally, we should be able to handle these cases:
    # w.x.y.z, .x.y.z, .y.z, .z
    # w.x.y.a-b, .x.y.a-b, .x.a-b, .a-b
    # w.x.y.z-a.b.c.d, w.x.y-a.b.c, w.x-a.b, w-a
    # we also need to be able to parse CIDR ranges.  Urgh.  w.x.y.z/0
    
    # ...but for the sake of simplicity we'll implement a subset, consisting of these cases:
    # 1. w.x.y.z
    # 2. w.x.y.z1-zN
    # 3. .z1-.zN

    currentNetwork = '0.0.0'
    groups = ipstring.split(',')    
    iplist = []
    for i in groups:

      octets = i.split('.')
      if len(octets) == 4:    # cases 1 and 2
        currentNetwork = "%s.%s.%s" % (octets[0],octets[1],octets[2])
        iprange = getRange(octets[3])
        ips = ["%s.%s" % (currentNetwork,i) for i in iprange]

      elif len(octets) == 2:  # case 3
            network = currentNetwork
            iprange = getRange(octets[1])
            ips = ["%s.%s" % (currentNetwork,i) for i in iprange]
        
      else:
        print 'syntax error in specifying host list!'
        sys.exit(1)
        
      iplist += ips

    return uniq(iplist)  # get rid of repeats


#  Main run
if __name__=='__main__':
    
    odfPage = None
    
    # parse arguments
    options, files = parseArgs( sys.argv )
    
    if options.portList:  options.portList =  parsePortList(options.portList)
    if options.hostList:  options.hostList = parseHostList(options.hostList)
    
    if options.severityList:

      # added "hole4" to account for the fact that some plugins have a "4" as their Severity.
      translateSeverities = {"critical_hole":"4", "hole":"3","warn":"2","note":"1","info":"0","openport":"0"}  # translate user input into numbers that Nessus now uses
      
      try:
         options.severityList = [translateSeverities[i] for i in options.severityList.split(',')]
         
      except KeyError:
          print "Error:  Severity options must be comma-separated list of words from the list [%s]" % ",".join(translateSeverities.keys())
          sys.exit(1)
      
    
    if options.riskFactorsList: options.riskFactorsList = options.riskFactorsList.split(',')
    if options.pluginIDList:  options.pluginIDList = parsePluginIDList(options.pluginIDList)
    
    printEntry = printEntryNormal
    if options.csvOutputFilename != "":  printEntry = printEntryCSV



    # ---- Load and parse Nessus scan results ----
    
    query = ResultsBase()
    DotNessusResults = DotNessusParser(query)
    NBENessusResults = NBENessusParser(query)
    
    for f in flatten([glob.glob(i) for i in files]):
        
        if f.endswith('.nessus'):
            DotNessusResults.loadFile(f)
            
        elif f.endswith('.nbe'):
            NBENessusResults.loadFile(f)


#    print 'available severities are %s' % {s.vuln['severity'] for s in query.results}
#    print "starting size of database is %d" % query.size()
            

    # ---- Apply constraints ----
    
    if options.portList:
        query.matchPort( options.portList )
        
    if options.hostList:
        query.matchHost( options.hostList )

    if options.severityList:
        query.matchSeverity(  options.severityList )
#        print 'size of database after matchSeverity() is %d' % query.size()
        
    if options.riskFactorsList:
#        print "matching riskFactors"

        rfList = [i.lower() for i in options.riskFactorsList]
        query.matchRiskFactors( rfList )
#        print 'size of database after matchRiskFactors() is %d' % query.size()        
        
    if options.contentQuery:  
        query.matchContentRegexp( options.contentQuery )
        
    if options.pluginIDList:
        query.matchPluginIDList( options.pluginIDList )


    # ---- collate and report results as per the user's request ----
    
    
    # output procedures below are sensitive to whether or not an ODF filename was specified
    # if so, then they output an ODF file.
    if options.odfOutputFilename is not '':  
        odfPage = ODFTable( options.odfOutputFilename )
        printEntry = odfPage.printEntry
         
    # open CSV output file, if specified
    if options.csvOutputFilename=="0":
       options.csvOutputFile = sys.stdout
    elif options.csvOutputFilename != "":
        options.csvOutputFile = open(options.csvOutputFilename, 'w')
#    else:
#        options.csvOutputFile = None

        
            
    
    if options.orderType=='h':  # output ordered by hosts
      num = 1
      for n in query.getVulnsByHost():
          printEntry(options, n, count=num)
          num += 1

    elif options.orderType=='g': # generate host file
      IPList = (ip for ip,results in query.getHosts())
      for ip in ipsort(IPList):
        print ip
        
    elif options.orderType=='p': # output ordered by Nessus plugins
      num = 1
      for (vulnerability, results) in query.getVulnerabilities():
          sample = results[0]  
          hostIPList = (r.getIP() for r in results)
          printEntry(options, sample, hostIPList, count=num)
          num += 1
          
    elif options.orderType=='c': # output ordered by CVE
      num = 1
      
      for (vulnerability, results) in query.getHostsByCVE():
          sample = results[0]  
          hostIPList = (r.getIP() for r in results)
          printEntry(options, sample, hostIPList)
          num += 1          
          
#      print '%d match(s)' % query.getCount()

    # ---- Save and close output files ----
    
    if options.csvOutputFilename not in ["", "0"]:
        options.csvOutputFile.close()
        
    if odfPage is not None:
        odfPage.saveAndClose()
        

   

