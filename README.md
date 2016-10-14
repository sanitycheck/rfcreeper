# RFCreeper

RFCreeper is a WIP geolocation tracking tool which leverages information from network probe requests (802.11 management frames) against the Wigle.net war driving database to try to produce an accurate representation on where a target has been. Once a device's probe request has been sniffed relevant data will be displayed in the terminal. This information will include the devices MAC address, Vendor type, RSSI, ESSID, and the BSSID. After capturing this information you can then use RFCreeper to lookup access point information using the Wigle.net database. The results gathered from the Wigle database are then parsed into a KML file based on location and can be viewed in Google Earth. As of right now this application only supports single network lookups at a time and requires a Wigle.net account to use the API.

## Getting Started

As of right now RFCreeper is only a sigle file python script. All that needs to be done to get this application up and running is to install a few dependencies and use its built in function to create a database table. The reason we need to create this table is so that RFCreeper can look up Vendors for each device's MAC address 
### Installing Depencies 

A list of dependencies can be found here --> [requirements.txt](requirements.txt)

```
git clone https://github.com/sanitycheck/rfcreeper
cd rfcreeper
pip install -r requirements.txt
```

### Setup

This command download a text file from ieee.org that contains a list of Vendor types and their associated OUI. This will then be parsed into an sqlite database for RFCreeper to use.

```
python rfcreeper.py --updateOui
```

For the next command your NIC should be in monitor mode

```
python rfcreeper.py -i mon0
```
and you should recieve output similar to what is shown below.
<br >
<br >
**NOTE:**Depending on the capability of your wireless card the RSSI values might not necessarily be correct.
```
  DeviceVendor                          ClientMac           Probes                RSSI   TimeStamp                 
                                                                                                                   
  Seiko Epson Corporation               11:22:33:44:55:66   Fleming Residence     -256   Thu Oct 13 20:37:18 2016  
  Apple, Inc.                           77:88:99:AA:BB:CC   BACK 2 BACK           -256   Thu Oct 13 20:37:20 2016  
  Seiko Epson Corporation               DD:EE:FF:A1:A2:A3   09EA49-MG2900series   -256   Thu Oct 13 20:37:22 2016  
  Hewlett Packard                       A4:A5:A6:A7:A8:A9   Hershey1              -256   Thu Oct 13 20:37:23 2016  
  Samsung Electronics Co.,Ltd           A1:B1:C1:D1:E1:F1   The Canasians         -256   Thu Oct 13 20:37:23 2016  
  SAMSUNG ELECTRO-MECHANICS(THAILAND)   AC:DC:B2:B3:B4:BE   logans5               -256   Thu Oct 13 20:37:25 2016  
```

So if we can narrow down which device our target is using we can then start leveraging network names against the Wigle database

## Running the tests

To perform ESSID lookups and generate KML files from the returned results we need the following:
<br >
* A wigle account
* The name of the network your targeting
* A name for the KML file

After issuing the following command you should also be prompted to enter your account password.
```
python rfcreeper.py -T <NetworkName> -u <WigleUsername> -k <KmlName>
WARNING: No route found for IPv6 destination :: (no default route?)
Wigle.net Account Password: 
```

If you everything went well you should get the following output
```
[+] Logging into wigle client
[+] Searching wigle database
[+] Access Points found: 100
[+] Filtering results
[+] Done resolving AP information
[+] Generating KML from AP information
[+] DDWRT KML file generated successfully
```
### Analysing the KML file

The KML file  generated can now be analyzed using utilities such as google earth. The content within the kml is organised based on location and and associated sub locations. If reconnaissance has been done on the target prior to using rfcreeper it should be relatively easy deduce past locations where the target has been. That being said, This tool heavily relies on only a small fraction of access point information that has already been uploaded to the wigle.net.

![Alt text](/rfcreeper/GoogleEarth?raw=true "Optional Title")

## Author

Dustin Mallory

## License

This project is licensed under the GNU General Public License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Hat tip to anyone who's code was used
* Inspiration
* etc
