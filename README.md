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

And repeat

```
until finished
```

End with an example of getting some data out of the system or using it for a little demo

## Running the tests

Explain how to run the automated tests for this system

### Break down into end to end tests

Explain what these tests test and why

```
Give an example
```

### And coding style tests

Explain what these tests test and why

```
Give an example
```

## Author

Dustin Mallory

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Hat tip to anyone who's code was used
* Inspiration
* etc
