# RFCreeper

RFCreeper is a geolocation tracking tool which leverages information from network probe requests (802.11 management frames) against the Wigle.net war driving database to try to produce an accurate representation on where a target has been. The results gathered from the Wigle database are then parsed into a KML file based on location and can be viewed in Google Earth. As of right now this application only supports single network lookups at a time and requires a Wigle.net account to use the API.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisities

prettytable==0.7.2
pygeocoder==1.2.5
requests==2.11.1
scapy==2.3.2
simplekml==1.3.0
wget==3.2
wigle==0.0.4

```
git clone https://github.com/sanitycheck/rfcreeper
cd rfcreeper
pip install -r requirements.txt
```

### Installing

A step by step series of examples that tell you have to get a development env running

Say what the step will be

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
