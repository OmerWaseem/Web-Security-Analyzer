# Web Security Analyzer

TODO: This application takes a given HTML page, scans it and gives a summary for list of vulnerabilties if there are any. 

## Installation

Modules used :

flask (Flask, render_template, request, Response)
argparse 
bs4 (BeautifulSoup,Comment)
urllib.parse(urlparse)
requests
validators
yaml

subprocess(call)
hashlib
json

socket

## Usage

On Linux Ubuntu, go to app directory and initialize a virtual environment. 

To host a server in the virtual environment locally, enter the following in terminal after locating to directory where virtual environment is initialised:

```
source venv/bin/activate
```

Next, run the app by:

```
python3 app.py
```
Now the terminal will run the app and a link will be shown.

Copy the link and open it in a browser.

You can now enter the link of the webpage you want to analyze.

After analyzing the page and showing the result, you can go back and try another page using the go back button.
