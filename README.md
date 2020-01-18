# zeek-oui
Zeek script to enable OUI logging in the conn log

# Setting up
Download the script to your zeek host
```
wget https://raw.githubusercontent.com/iamckn/zeek-oui/master/oui-logging.zeek
sudo mv oui-logging.zeek /usr/local/zeek/share/zeek/policy/protocols/conn/
```

Download your oui mapping file to your zeek host
```
wget https://raw.githubusercontent.com/iamckn/zeek-oui/master/oui.dat
sudo mv oui.dat /usr/local/zeek/share/zeek/policy/protocols/conn/
```
Load the script by editing the file - /usr/local/zeek/share/zeek/site/local.zeek
```
@load policy/protocols/conn/oui-logging
```
