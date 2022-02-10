# Regex Tips
## Regular Expression - SED - Regex.
- http://sed.sourceforge.net/grabbag/tutorials/do_it_with_sed.txt

## Change extension.
find . -name '*.txt' | sed 's/.*/mv & &/' | sed 's/\.txt$/.tec/'

*****************************************************************
## Random number generator.
echo $(( $RANDOM % 100))
- http://aurelio.net/blog/2013/05/10/video-aula-sorteio-no-facebook-usando-shell-script/

*****************************************************************
## Find a specific line.
cat lista.txt | sed -n 3p

*****************************************************************
## Regex IPv4
([0-9]{1,3}(\.[0-9]{1,3}){3})
## Regex IPv6
([a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})

*****************************************************************

## Change key with extension .PPK (PUTTY) to Linux Format 
for X in *.ppk; do puttygen $X -L > ~/.ssh/$(echo $X | sed 's,./,,' | sed 's/.ppk//g').pub; puttygen $X -O private-openssh -o ~/.ssh/$(echo $X | sed 's,./,,' | sed 's/.ppk//g').pvk; done;

*****************************************************************
## Add "/32" in the last line.
sed 's/$/\/32/'

## Add the "set address office365-" in front line and change "." to "-", finally with "--32".
sed 's/^/set address office365-/' | sed 's/\./-/g' | sed 's/$/\--32/'

## Remove line with that have "/"
sed '/\//d'
ex.:
192.178.10.20/23

sed 's:\/:--:g' FILE.txt | sed 's:\.:-:g'

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
Ex: "carlos.jose"
sed -n '/\./p' usuario | uniq

*****************************************************************
## Change from line to column, or from column to line.
```
:%s/,/\r/g

change (,) to next line.

Exemplo.
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
![image](https://user-images.githubusercontent.com/80328830/153414533-c0e877a3-b558-4077-b6f2-db42b86319ef.png)

*****************************************************************
## Files chi
[^\x00-\x7F]+\ *(?:[^\x00-\x7F]| )*.exe

*****************************************************************
## URL Validation
[(http(s)?):\/\/(www\.)?a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)

## Ip Address
\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b

*****************************************************************
## Timespan
^((([0-1]?[0-9])|([2][0-3])):)?(([0-5][0-9]):)?([0-5][0-9])(\.\d{1,3})?$|^\d+(\.\d{1,3})?$

## Extenções
(\.\+w|.js|.exe|.doc|.txt|.rar|.tar|.pdf|.img|.xlsx$)

## URL que contem
(.ttp[s]?\:.*(.php|.zip|.bat|.exe|.src|.run\$))
([^Received:]\s+(.*from\s).*)(\.sebraego.com.br)

## Contem "From na primeira Linha e pula (\n+) procurando sebraego"
((.*From.*[\n+].*)sebraego\.com\.br.*)

*****************************************************************
## CPF
([0-9]{3}\.[0-9]{3}\.[0-9]{3}\-[0-9]{2})

## Faz match em palavras que contem o caracter $
(\w+.?[\$]) ou (\w+[\$])
\w+[\$]|((SRV)\w+)|((srv)\w+)
SRVLAV$ ou $SRVLAB ou SRVLAB ou srvLaB
(\w+[$]|[$]+\w+)

*****************************************************************

## Match todos dominios abaixo
.*\.(ly|cn|kp|ira|fy|af|ss|cu|iq|il|ye|ir|ru).*

## Match todo final de URL https/http
(.*tps?:\/\/.*(\.exe|\.vbs|\.php|\.sh|\.jar|\.zip|\.bat|\.js|\.cmd|\.src$))

## Match todos que começam ou que contem
(.*www-data@.*)|(.*@localhost.*)

## Match todos que começam com letras e numeros inclusive no codigo fonte.
(.*[\d]@.*)

## Match todos que terminal com clique aqui ou clique
(.*tps?:\/\/)(.*[Cc]lique?.*aqui|.*[Cc]lique$)
(.*tps?:\/\/.*(\.php|\.sh|\.cmd|\.exe|\.bat|\.vbs|\.jar|\.js|\.src|\.aspx).*)
(.*tps?:\/\/.*(\.exe|\.vbs|\.php|\.sh|\.jar|\.zip|\.bat|\.js$))

## Tirar o traço ( ,) no final da frace e pular a linha. ex. xpto,dcdar,acdacd
sed 's/,/\n/g'

## Buscar um ou outro
cat malware | grep -Ev "micros|google|sebrae|linke|skype|portaldoem|facebook|gov.br|icloud|footprintdns"
lynx --source https://ransomwaretracker.abuse.ch/ip/209.99.40.222/ | awk {'print $3}' | sed 's/href\=\"host\///' | sed 's/\/\"//'

*****************************************************************
## Get Details about some Malware IP
curl --request GET --url 'https://www.virustotal.com/vtapi/v2/ip-address/report apikey=1e73f5e9573b8a85a9f4118b39071a9d3f89849ab98f935bc611e5b457bf8e9f&ip=209.99.40.222'

{"last_resolved": "2015-09-18 00:00:00", "hostname": "019582.yihedu.com"}

cat file1  | sed 's/,/\n/g' | grep hostname | awk '{print $2}' | sed 's/\"}//' | sed 's/\"//'
cat file1  | sed 's/,/\n/g' | grep url | awk '{print $2}' | sed 's/\"//' | sed 's/http\:\/\///' | sed 's/\/.*//' | sort -u

*****************************************************************

## Inserir "*" no inicio das linhas
sed 's/^#*/*/' 

## Inserir "*" no final das linhas
sed 's/$/*/'

## Removendo linhas vazias com sed
cat file.txt | sed '/^$/d'

## Pegar informações de um IP no VirusTotal
curl --request GET --url 'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=1e73f5e9573b8a85a9f4118b39071a9d3f89849ab98f935bc611e5b457bf8e9f&ip=209.99.40.222' | sed 's/},/\n/g' | grep url | awk '{print $2}' | sed 's/\"//' | sed 's/http\:\/\///' | sed 's/\/.*//' | sort -u | sed 's/^#*/*/' | sed 's/$/*/'

*****************************************************************

(^DWM|^DicomServer|^DefaultAppPool|^schedule.tasks|^AppVPublishing|^Symantec|^postgres|^Classic|^synapseae|^altaperformance|^.NET\s)|(\w+[$])

## Remover ^M do script ou arquivo
sed -e "s/\r//g" file > newfile
ou
dos2unix script

## How to convert a string from uppercase to lowercase
cat file.txt | tr '[:upper:]' '[:lower:]'
*****************************************************************