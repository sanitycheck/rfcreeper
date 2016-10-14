#!/usr/bin/python -w
# Author: Dustin Mallory
# Name: rfcreeper
# Version: 1.0
# Description: rfcreeper is a geolocation tracking tool which leverages information from network probe requests 
#              to both actively track and create profiles on targets.
# CHANGE LOG
# Author           Date         Description
# Dustin Mallory | 01/12/2016 | Geolocation tracking tool
#
#
#

from scapy.all import *
from prettytable import PrettyTable
from prettytable import PLAIN_COLUMNS
from wigle import Wigle
from pygeocoder import Geocoder
import wget
import simplekml
import logging
import time
import string
import urllib2
import sqlite3
import optparse
import sys
import os
import re

logging.basicConfig(filename='rfcreep.log', level=logging.INFO)
logging.captureWarnings(True)
logging.info('Logging started @' + time.strftime('%c'))
reload(sys)
sys.setdefaultencoding('UTF8')

parser = optparse.OptionParser(description="geolocation tracking\nUsage: python {0} <arguments>".format(os.path.basename(__file__)))
parser.add_option('-i',
                  dest='iface',
                  type='string',
                  help='Specify an interface to capture on (i.e. mon0)')
parser.add_option('--updateOui',
                  action='store_true',
                  dest='UpdateOui',
                  help='This option will update the tables in the vendor database')
parser.add_option('--dbs',
                  dest='DBhandle',
                  type='string',
                  help='Specify a database to create or connect to.')
parser.add_option('-w',
                  dest='PcapName',
                  type='string',
                  help='Captures packets on the specified interface and write to pcap file')
parser.add_option('-u',
                  dest='FileUpload',
                  type='string',
                  help='Specify file(s) to upload to google drive')
parser.add_option('-k',
                  dest='KMLFilename',
                  type='string',
                  help='Generates KML file from enumerated networks')
parser.add_option('-T',
                  dest='TargetNetwork',
                  type='string',
                  help='Specify a target network to enumerate')
parser.add_option('-d',
                  dest='DisFilter',
                  action='store_true',
                  help='Disabling expensive filtering will allow kml files to be generated quickly at the cost of organization')
parser.add_option('--ScanName',
                  dest='ScName',
                  type='string',
                  help='Scans area network probe requests in area to see if target is within range. Scanning via name will only work if target MAC address is already stored in database')
parser.add_option('--ScanMac',
                  dest='ScMac',
                  type='string',
                  help='Scans area for target via MAC address')
parser.add_option('--ScanEssid',
                  dest='ScESSID',
                  type='string',
                  help='Scans area for devices probing for a specific network name')
(options, args) = parser.parse_args()



class RFcreeper:

    """RFcreep is a tool designed for geolocation tracking. Its designed to sniff network probe requests from 
       other wireless enabled devices. The information captured from these probe requests is then stored in a 
       database for further processing"""

    def __init__(self):
        
        #self.pktcount = 0
        self.HomeDir = os.path.expanduser('~')
        self.WriteDir = self.HomeDir + '/rfcreeper/'
        self.DatabaseName = 'RFcreeper.db'
        self.TableName = 'target'
        self.VendorTable = 'VendorTable'
        self.WigleResults = {}
        self.ExpensiveFiltering = True
        self.OutputData = PrettyTable("DeviceVendor ClientMac Probes RSSI TimeStamp".split())
        #self.OutputData.set_style(PLAIN_COLUMNS)
        self.OutputData.vertical_char = ' '
        self.OutputData.horizontal_char = ' '
        self.OutputData.junction_char = ' '
        self.OutputData.align = 'l' 
        self.InfoList = []
        self.ClientMac = None
        self.MacPrefix = None
        self.ClientOui = None
        self.RSSI = None
        self.BSSID = None
        self.ESSID = None
        self.TimeStamp = None
        self.OuiUrl = "http://standards-oui.ieee.org/oui.txt"#"http://www.standard-oui.ieee.org/oui/oui.txt"

        if self.dir_writeable(self.HomeDir) == True:
            os.system("mkdir -p {0}".format(self.WriteDir))
            self.DBConnect = sqlite3.connect(self.WriteDir + self.DatabaseName)
            self.DBConnect.text_factory = str
            self.DBHandle = self.DBConnect.cursor()
        else:
            print "[-] You do not have write permissions for {0}".format(self.WriteDir)
            exit(1)
    
    
    def PacketHandler(self, pkt):

        #self.pktcount += len(pkt)

        # Determines if the packet is a network request probe
        #print "\r" + str(self.pktcount)
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 4:
                if self.is_printable(pkt.info) and pkt.info and pkt.addr2:
                    self.ClientMac = pkt.addr2.upper()
                    self.FindOui(self.ClientMac)
                    self.BSSID = pkt.addr3
                    self.ESSID = pkt.info
                    #print len(pkt.notdecoded)
                    #print "----start----"
                    #for i in range(len(pkt.notdecoded)):
                        #print ord(pkt.notdecoded[i])
                    #print "----end----"
                    self.RSSI = (ord(pkt.notdecoded[-4:-3])-256)
                    self.TimeStamp = time.strftime("%c")
                    #print self.TimeStamp.split()
                    values = [self.ClientOui, self.ClientMac, self.BSSID, self.ESSID] + self.TimeStamp.split()
                    #values.append(self.TimeStamp)
                    #print values
                    #print "Device Vendor: {0}\t\tClient Mac: {1} => BSSID: {2} ESSID: {3}\t\tTimeStamp: {4}".format(self.ClientOui, self.ClientMac, self.BSSID, self.ESSID, self.TimeStamp)
                    results = [self.ClientOui, self.ClientMac, self.BSSID, self.ESSID]#, self.TimeStamp]
                    FullData = [self.ClientOui, self.ClientMac, self.ESSID, self.RSSI, self.TimeStamp]
                    if results not in self.InfoList:
                        self.InfoList.append(results)
                        self.OutputData.add_row(FullData)
                        os.system('clear')
                        print self.OutputData
                    self.CreateTable(tablename = self.TableName, 
                                     ColumnNames = ['DeviceVendor','ClientMAC', 'BSSID', 'ESSID', 'Day', 'Month', 'Date', 'Time', 'Year'],#, 'FullDate'],
                                     ColumnValues = values)
 
    def ResolveAP(self, TargetNetwork):
        
        """This function is used to resolve information returned from wigle and
           sort it into a multi-dimensional associative array"""

        print "[+] Logging into wigle client"
        wigle = Wigle('icee41','OREOMArb') # username and password NOTE careful how much information (and how fast) you query as wigle.net has a cap lim
        print "[+] Searching wigle database"
        results = wigle.search(ssid=TargetNetwork)
        APNumber = len(results)
        KeyCount = 1
        print "[+] Access Points found: %s" % (APNumber)
        print "[+] Filtering results"
        for AccessPoint in results:
            KeyName = TargetNetwork + ' ' + str(KeyCount)
            name = AccessPoint['ssid']
            if name != TargetNetwork: #Only store case sensitive results
                continue
            lat = AccessPoint['trilat']
            lon = AccessPoint['trilong']
            bssid = AccessPoint['netid']
            vendor = self.FindOui(bssid)
            channel = AccessPoint['channel']
            location = self.GetLocation(lat,lon)

            if AccessPoint['wep'] == 'Y':
                AccessPoint['wep'] = 'WEP'
            elif AccessPoint['wep'] == 'N':
                AccessPoint['wep'] = 'None'
            elif AccessPoint['wep'] == 'W':
                AccessPoint['wep'] = 'WPA'
            elif AccessPoint['wep'] == '2':
                AccessPoint['wep'] = 'WPA2'
            else:
                AccessPoint['wep'] = 'Unknown'

            self.WigleResults[KeyName] = { 'Network Name' : TargetNetwork,
                                           'Vendor' : vendor,
                                           'Encryption' : AccessPoint['wep'],
                                           'Visible' : AccessPoint['visible'],
                                           'BSSID' : bssid,
                                           'Channel' : channel,
                                           'Latitude & Longitude' : str(lat) + ', ' + str(lon),
                                           'Location' : location,
                                           'Last Seen' : AccessPoint['lasttime'] }
            KeyCount += 1
        print "[+] Done resolving AP information"

    def KmlWriter(self, filename):
        print "[+] Generating KML from AP information"
        kml = simplekml.Kml()

        # use associative arrays to call upon instances of dynamically created folders and subfolders
        CountryDict = {}
        StateDict = {}
        CityDict = {}

        for ap in self.WigleResults:
            point = None
            lat, lon = self.WigleResults[ap]['Latitude & Longitude'].replace(',','').split()
            if self.ExpensiveFiltering == True:
                try:
                    Country = self.WigleResults[ap]['Location'][0].country # assign country attribute from location array
                    State = self.WigleResults[ap]['Location'][0].state # assign state variable
                    City = self.WigleResults[ap]['Location'][0].city # assign city variable
                    
                    if State == None:
                        State = self.WigleResults[ap]['Location'][0].county

                    if Country not in CountryDict: # if the country key isnt in the associative array then neither is an instance for its created folder
                        folder = kml.newfolder(name=Country) # create the instance
                        CountryDict[Country] = folder # and assign it a key in the dictionary
                    else:
                        folder = CountryDict[Country] # else call upon the instance already in the dictionary
                        
                    if State not in StateDict: # if the state key is not in the dictionary
                        folder = folder.newfolder(name=State) # create a 'state' folder instance
                        StateDict[State] = folder # assign instance to state key
                    else:
                        folder = StateDict[State] # else call state instance, to avoid creation of unnecessary folders
    
                    if City not in CityDict: 
                        folder = folder.newfolder(name=City)
                        CityDict[City] = folder
                    else:
                        folder = CityDict[City]
    
                except AttributeError: 
                    """the attribute error occurs when a certain attribute does not exist. if this happen then the point
                       is place outside of the organized folders"""
                    point = kml.newpoint(name=self.WigleResults[ap]['Network Name'], coords=[(lon,lat)])
            else:
                point = kml.newpoint(name=self.WigleResults[ap]['Network Name'], coords=[(lon,lat)])
            
            description = """Vendor: {0}
                             Encryption: {1}
                             Visible: {2}
                             BSSID: {3}
                             Channel: {4}
                             Latitude & Longitude: {5}
                             Location: {6}
                             Last Seen: {7}""".format( self.WigleResults[ap]['Vendor'],
                                                       self.WigleResults[ap]['Encryption'],
                                                       self.WigleResults[ap]['Visible'],
                                                       self.WigleResults[ap]['BSSID'],
                                                       self.WigleResults[ap]['Channel'],
                                                       self.WigleResults[ap]['Latitude & Longitude'],
                                                       self.WigleResults[ap]['Location'],
                                                       self.WigleResults[ap]['Last Seen'] )
            if point == None:
                folder = folder.newpoint(name=self.WigleResults[ap]['Network Name'], coords=[(lon, lat)])
                folder.description = description
            else:
                point.description = description

        kml.save(self.WriteDir + filename+'.kml')
        print "[+] %s KML file generated successfully" % (filename)


    def GetLocation(self, lat, lon):
        # Get location from latitude and longitude coordinates
        return Geocoder.reverse_geocode(lat, lon)

    def dir_writeable(self, directory):
        
        # Determines if directory is writeable
        return os.access(directory, os.W_OK)

    def file_exists(self, filename):
        return os.path.isfile(filename)

    def dir_exists(self, directory):
        return os.path.exists(directory)
    
    def OuiUpdate(self): # NOTE Finish ParseOui function for use with update
        if self.checkTableExists(self.VendorTable) == False:
            print "[-] No table found...Downloading update"
            filename = wget.download(self.OuiUrl, out=self.WriteDir)
            print "[+] Update Downloaded"
            print "[+] Parsing OUI information into database table..."
            self.ParseOui()
            print "[+] Done"
            print "[+] Table Updated"
        else:
            print "[-] Table not updated"

    def ParseOui(self): # NOTE Finish parsing and store data in database-
        Oui = self.WriteDir + self.OuiUrl.split('/')[-1]
        queries_list = []
        with open(Oui) as update:
            for line in update:
                if re.search("(hex)", line):
                    line = re.sub("\(hex\)", '', line)
                    line = " ".join(line.split())
                    queries = line.split(' ',1)
                    queries_list.append(queries)
        if self.checkTableExists(self.VendorTable):
            self.DropTable()
            self.CreateTable(tablename = self.VendorTable,
                             ColumnNames = "OUI Vendor".split(),
                             ColumnValues = queries_list)
        else:
            self.CreateTable(tablename = self.VendorTable,
                             ColumnNames = "OUI Vendor".split(),
                             ColumnValues = queries_list)



    def FindOui(self, mac):
        # prepare client OUI via substitution and slicing of the MAC Address
        self.MacPrefix = re.sub(r':', r'-', mac)[:8]
        query = """SELECT Vendor FROM {0} WHERE OUI='{1}'""".format(self.VendorTable, self.MacPrefix)
        try:
            self.DBHandle.execute(query)
            self.ClientOui = self.DBHandle.fetchone()[0]
        except TypeError:
            self.ClientOui = "NO DATA FOUND"

    
    def checkTableExists(self, tablename):

        self.DBHandle.execute("""SELECT * FROM sqlite_master WHERE name='{0}' and type='table'""".format(tablename))
        try:
            self.DBHandle.fetchone()[0]
            return True
        except TypeError:
            return False
            
    
    def is_printable(self, SSID):

        # checks for malformed packet info (SSID)
        return all(char in string.printable for char in SSID)

    
    def AddRecord(self, tablename, ColumnNames, values): #ADD COLUMN NAME PARAMETER HERE LATER
        
        DynValues = ','.join('?' * len(ColumnNames))
        query = "INSERT OR IGNORE INTO {0}({1}) VALUES ({2})".format(tablename, ",".join(ColumnNames), DynValues)
        if len(values) >= 18:
            self.DBHandle.executemany(query, values)
        else:
            self.DBHandle.execute(query, values)
        self.DBConnect.commit()

    
    def CreateTable(self, tablename, ColumnNames, ColumnValues):

        if self.checkTableExists(tablename):
            self.AddRecord(tablename, ColumnNames, ColumnValues)
        else: 
            DynColumn = ""
            counter = 1
            query = """CREATE TABLE {0} ("""
            for columns in ColumnNames:
                DynColumn = DynColumn + '{' + str(counter) + '} text, '
                counter += 1
            DynColumn = DynColumn[:-2] + ')'
            query = query + DynColumn
            self.DBHandle.execute(query.format(tablename, *ColumnNames))
            self.AddRecord(tablename, ColumnNames, ColumnValues)
   

    def DropTable(self):
        query = "DROP TABLE {0}".format(self.VendorTable)
        self.DBHandle.execute(query)



def main():
    traffic = RFcreeper()
    # make sure that args that explicitly affect program variables i.e. filtering come first
    if options.DisFilter == True:
        traffic.ExpensiveFiltering = False
    if options.TargetNetwork:
             traffic.ResolveAP(options.TargetNetwork)
             traffic.KmlWriter(options.KMLFilename)
    
    if options.UpdateOui == True:
        traffic.OuiUpdate()
    if options.iface:
        while True:
            try:
                sniff(iface=options.iface, prn = traffic.PacketHandler)
            except AttributeError:
                pass
            else:
                traffic.DBHandle.close()
                break
        


if __name__ == "__main__":
    main()
logging.info('Logging Finished @' + time.strftime('%c'))



