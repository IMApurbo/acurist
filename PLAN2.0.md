# Hackers Ai
## motive
**We are gonna build a Ai assistant/Agent, which will work as an ultimate computer assisstant, it may have a detailed idea about Linux built-in tools, important files, additional tools, and their uses(`uses not mandatory because each tool has -h flags for uses`). using 2 main method (`running command and creating temporary python file to complete the task and execute the .py file, then delete the temp file`) only create and run python file when its not possible to directly complete the task via command**

## capablities:
* can analyze/generate/create/update/delete any kind of files(`eg. txt,pdf,.py,.c,mp3,mp4,pcap, csv, json etc`)
* have the general talking cablity and the ability to remember previous conversation (`eg. 10`)
* can run linux tools(`eg, ping,top,neofetch,curl,wget,nmap,hydra,wireshark,tshark, metasploit,ettercap,bettercap`) and others from `https://www.kali.org/tools`, but here is a catch , if any error occured , it will feed the error back to the ai , so ai craft another command to resolve it , if it want to use any tool for any task , so it will generate the complete command for the task and run it , if there any issue related to wrong uses of tools (`eg, wrong flags`)  like it generate **ping -x 123.123.123** and if there are not flag -x for ping , then this will check tool help menu by `-h` and reading the output will will try to recarft command and run again.
* it can identify and test vulnareblity
  - web vuln like `xss,sqli,dir_brute,subdomain_enum,domain_info, brute_forcing,lfi,command_injection,csrf,ssrf,file upload etc`
  - wireless attacks like `scanning_for_networks,running_attacks like wps,wpa,evil_tween,deauth,fake/evil_ap,wifiphishing,multiple_ap etc` 
  - and many more
* after first run , it will store key information from the os like os name ,and others , according to the info ,so this use the default files and installtion path , default applicatios , easily.
* using free ai from `freellm` documentation link `https://pypi.org/project/freellm`
* it only run with sudo , and if not provided then it show a message and exit 
* it free to install nessassary python libs , when doing any task completed via creating and running py file. others linux tools also via   `snapd,apt,git,pypi` etc
* clear past mem each time the tool restarted
* it save some modes and fixed keywords which can by triggered by `/`
    - `/clear` clear previous conersation history from mem 
    - `/exit` edit the tool 
    - `/switch "<model_name>"` switch the ai model

* smart summerized answer from ai 
* show commands output on terminal real time(`not for those tools which doesnt show output on terminal`)
    
## working procedure

* it have a stong promt so the ai response like that so python can grab the response and use it `eg, json`
*  first it will understand 2 thing , it is a gretting or informational thing? or its a task to execute or both examples,
    - `tell me about my system` "informative and command" because it need to run command to check system info and then response and tell anser of the question
    - `what is hacking` "informative" no command execution or temp python need
    - `is this url https://example.com/search?quary=books vulnareble to xss?` command execution need
* after that , if its a task or information +task, where command execution or python execution need , then it will generate plan and steps  and show it on terminal and ask user to press `y` to continue and `n` to stop
* if yes then show steps execution of command or py file or the ida, and use separete mem for storing steps for current task , so it can stotre the plan and , running steps command grabing output feed it back to ai and continue for second steps based on that.

* 

