# pyMFA
pyMFA implements the Google Authenticator method of generating MFA codes. If a platform supports Google Authenticator, it will work here as well.

## Usage
Create a file `mfa-data.csv` with the headers as `secret,name`. Feel free to add as many sources as you'd like. The code will refresh every 30 seconds automatically. Press `CTRL+C` to exit the script.

## Thanks
* Pseduocode from [Wikipedia](https://en.wikipedia.org/wiki/Google_Authenticator).
* Adopted from excellent GoLang implementation by [tilaklodha](https://medium.com/@tilaklodha/google-authenticator-and-how-it-works-2933a4ece8c2).