# Regex Tips
## Regular Expression - SED - Regex.
- http://sed.sourceforge.net/grabbag/tutorials/do_it_with_sed.txt

## Change extension.
```
find . -name '*.txt' | sed 's/.*/mv & &/' | sed 's/\.txt$/.tec/'
```
*****************************************************************
## Random number generator.
echo $(( $RANDOM % 100))
- http://aurelio.net/blog/2013/05/10/video-aula-sorteio-no-facebook-usando-shell-script/

*****************************************************************
## Find a specific line.
cat lista.txt | sed -n 3p

*****************************************************************
## Regex IPv4
```
([0-9]{1,3}(\.[0-9]{1,3}){3})
```
## Regex IPv6
```
([a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})
```
*****************************************************************

## Change key with extension .PPK (PUTTY) to Linux Format 
```
for X in *.ppk; do puttygen $X -L > ~/.ssh/$(echo $X | sed 's,./,,' | sed 's/.ppk//g').pub; puttygen $X -O private-openssh -o ~/.ssh/$(echo $X | sed 's,./,,' | sed 's/.ppk//g').pvk; done;
```
*****************************************************************
## Add "/32" in the last line.
```
sed 's/$/\/32/'
```
## Add the "set address office365-" in front line and change "." to "-", finally with "--32".
```
sed 's/^/set address office365-/' | sed 's/\./-/g' | sed 's/$/\--32/'
```
## Remove line with that have "/"
```
sed '/\//d'
ex.:
192.178.10.20/23

sed 's:\/:--:g' FILE.txt | sed 's:\.:-:g'
```
*****************************************************************
## Remove empty line.
### sed
```
'/^\[\[:space:\]\]*$/d'
'/^\s*$/d'
'/^$/d'
-n '/^\s*$/!p'
```
### grep
```
-v '^$'
-v '^\s*$'
-v '^\[\[:space:\]\]*$'
```
### awk
```
/./
'NF'
'length'
'/^[ \t]*$/ {next;} {print}'
'!/^\[ \t\]*$/'
```
*****************************************************************
## Find out users that content name with "." in file.
```
Ex: "carlos.jose"
sed -n '/\./p' usuario | uniq
```
*****************************************************************
## Change from line to column, or from column to line.
```
:%s/,/\r/g

change (,) to next line.

sample.
teste1,teste2,teste3,teste4,teste5
to:
teste1
teste2
teste3
teste4
teste5

the other way around.

:%s/\n/\,/g

teste1
teste2
teste3
.
.
.
to
teste1,teste2,teste3 ...
```
*****************************************************************
## Add "#" or something in some line range on Vim editor.
```
:start line,last line/^/#
Sample:

:4,10s/^/something

```
![image](https://user-images.githubusercontent.com/80328830/153415421-e6e1fce3-14d5-45b6-b4ed-1e661a314e89.png)

### to

![image](https://user-images.githubusercontent.com/80328830/153415657-79e8bf2a-35ad-4675-8ff3-d93dfd1884c0.png)


*****************************************************************
## Files chi
```
[^\x00-\x7F]+\ *(?:[^\x00-\x7F]| )*.exe
```
*****************************************************************
## URL Validation
```
[(http(s)?):\/\/(www\.)?a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)
```
## Ip Address
```
\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b
```
*****************************************************************
## Timestamp
```
^((([0-1]?[0-9])|([2][0-3])):)?(([0-5][0-9]):)?([0-5][0-9])(\.\d{1,3})?$|^\d+(\.\d{1,3})?$
```
# Extensions (used in AntiSpam Symantec)
```
(\.\+w|.js|.exe|.doc|.txt|.rar|.tar|.pdf|.img|.xlsx$)
```
### Content in URL
```
(.ttp[s]?\:.*(.php|.zip|.bat|.exe|.src|.run\$))
([^Received:]\s+(.*from\s).*)(\.sebraego.com.br)
```
### Content "From in first line and jump (\n+) searching for google.com"
```
((.*From.*[\n+].*)google\.com.*)
```
### Match all domain below
```
.*\.(ly|cn|kp|ira|fy|af|ss|cu|iq|il|ye|ir|ru).*
```
### Match the last URL content https/http
```
(.*tps?:\/\/.*(\.exe|\.vbs|\.php|\.sh|\.jar|\.zip|\.bat|\.js|\.cmd|\.src$))
(.*tps?:\/\/.*(\.php|\.sh|\.cmd|\.exe|\.bat|\.vbs|\.jar|\.js|\.src|\.aspx).*)
(.*tps?:\/\/.*(\.exe|\.vbs|\.php|\.sh|\.jar|\.zip|\.bat|\.js$))
```
### Match all content below
```
(.*www-data@.*)|(.*@localhost.*)
```
### Match all words and number including code font.
```
(.*[\d]@.*)
```
### Match all phrases that content "clique" or "clique aqui"
```
(.*tps?:\/\/)(.*[Cc]lique?.*aqui|.*[Cc]lique$)
```
*****************************************************************
## CPF
```
([0-9]{3}\.[0-9]{3}\.[0-9]{3}\-[0-9]{2})
```
## Match in words that content "$"
```
(\w+.?[\$]) ou (\w+[\$])
\w+[\$]|((SRV)\w+)|((srv)\w+)
SRVLAV$ or $SRVLAB or SRVLAB or srvLaB
(\w+[$]|[$]+\w+)
```
*****************************************************************

## Remove "," and jump to next line
```
sed 's/,/\n/g'
```
## Find out string or anything using "|" with grep command
```
cat malware | grep -Ev "micros|google|sebrae|linke|skype|portaldoem|facebook|gov.br|icloud|footprintdns"

```
*****************************************************************
## Get Details about some Malware IP
```
curl --request GET --url 'https://www.virustotal.com/vtapi/v2/ip-address/report apikey=1e73f5e9573b8a85a9f4118b39071a9d3f89849ab98f935bc611e5b457bf8e9f&ip=209.99.40.222'

{"last_resolved": "2015-09-18 00:00:00", "hostname": "019582.yihedu.com"}

cat file1  | sed 's/,/\n/g' | grep hostname | awk '{print $2}' | sed 's/\"}//' | sed 's/\"//'
cat file1  | sed 's/,/\n/g' | grep url | awk '{print $2}' | sed 's/\"//' | sed 's/http\:\/\///' | sed 's/\/.*//' | sort -u
```
*****************************************************************

## add "*" in the start line
```
sed 's/^#*/*/' 
```
## add "*" in the last line
```
sed 's/$/*/'
```
## Remove the empty line with SED
```
cat file.txt | sed '/^$/d'
```
## Get IP information using the VirusTotal API command
```
curl --request GET --url 'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=1e73f5e9573b8a85a9f4118b39071a9d3f89849ab98f935bc611e5b457bf8e9f&ip=209.99.40.222' | sed 's/},/\n/g' | grep url | awk '{print $2}' | sed 's/\"//' | sed 's/http\:\/\///' | sed 's/\/.*//' | sort -u | sed 's/^#*/*/' | sed 's/$/*/'
```
*****************************************************************

## Remove "^M"
```
sed -e "s/\r//g" file > newfile
ou
dos2unix script
```
## How to convert a string from uppercase to lowercase
```
cat file.txt | tr '[:upper:]' '[:lower:]'
```
*****************************************************************
# Anything
```
(^DWM|^DicomServer|^DefaultAppPool|^schedule.tasks|^AppVPublishing|^Symantec|^postgres|^Classic|^synapseae|^altaperformance|^.NET\s)|(\w+[$])

lynx --source https://ransomwaretracker.abuse.ch/ip/209.99.40.222/ | awk {'print $3}' | sed 's/href\=\"host\///' | sed 's/\/\"//'
```
