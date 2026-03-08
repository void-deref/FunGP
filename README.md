## FunGP
This application is intended to ease the management of the 'java card' based smart and SIM cards.

## Presequisites
python 3.12  
On Windows: just download the installer from the python.org.  
On Ubuntu: `sudo apt install python3.12 python3.12-venv python3.12-dev python3.12-pip`.

## Working environment
1. download project
2. change to FunGP folder
3. create virtual environment: `> python -m venv .venv`
4. activate environment:  
On Windows: `> .venv\Scripts\activate.bat`  
On Ubuntu: `> source .venv/bin/activate`
5. install `> pip install -e .` this is the local installation of the FunGP package and its dependencies
6. optional: deactivate environment before leaving the project:  
On Windows: `> .venv\Scripts\deactivate.bat`  
On Ubuntu: `> deactivate`  


## Running smart card examples
1. change to ./tests/smart_card
2. open 05_install_for_install_test.py
3. set the `known_readers` variable with the name of your reader. To get such info just run this script - before falling with error it will display a list of available readers:  
```shell
Context established.
Available PCSC readers:
    ACS ACR39U ICC Reader 0
>> 00A40400 08 A000000151000000
Traceback (most recent call last):
--//--
```
4. run the script. It will install the SimpleApplet.cap file which resides in ./resources folder.

## Running uicc exmaple
1. change to ./tests/uicc
2. open 01_scp80_test.py
3. set the `known_readers` variable with the name of your reader. To get such info just run this script - before falling with error it will display a list of available readers:  
```shell
Context established.
Available PCSC readers:
    ACS ACR39U ICC Reader 0
>> 00A40400 08 A000000151000000
Traceback (most recent call last):
--//--
```
4. update the `iccid` global variable with the correct ICCID value of your SIM-card
5. write to the `./resources/known-simcards.json` correct values of your SIM card (ICCID, CNTR and keys)
6. write to the `tar_value` global variable  a correct value of your application TAR
7. ensure that `uicc.apdu_scp80()` gets a correct params

### Task list
- [+] connection establishment with smart card
- [ ] parsing ATR
- [+] `apdu transmit` command
- [+] `get response` command
- [+] `SCP02` protocol
- [ ] parsing a data fetched be means of GET DATA command
- [ ] parsing a data fetched be means of GET STATUS command
- [+] `install[for load]` command
- [+] `load` command
- [+] `install[for install]` command
- [+] `install[for install and make selectable]` command
- [+] `delete` command
- [+] `SCP80` protocol



## References
| Specification | Description |
| --------------- | --------------- |
| GlobalPlatform v2.3.1 | The base. This release marked SCP02 as deprecated and have appended additional zeros to ISD AID.|
| GlobalPlatform v2.0 Common Implementation Configuration  | Defines a configuration of (but not limited to) SCP02, Card capability information, APDU commands etc |
| GlobalPlatform v1.0 ISO Framework | Mapping of ISO entities to the realm of GP |


## Notes

### INSTALL command (GP 2.3, clause 11.5)

Initiates various steps required for Card Content management.  

```shell
CLA: 80  
INS: E6  
P1: b8 == 0 - last or only  
    b8 == 1 - more INSTALL commands  
    40      - for registry update  
    20      - for personalization  
    10      - for extradition
    0 1xx0  - for make selectable (requests to make applet selectable)
    0 x1x0  - for install (requests the installation of an applet)
    0 xx10  - for load (serves as the load request for loading)
P2: 00 - no info
    01 - beginning of the combined load, install and make selectable
    03 - the end of the combined load, install and make selectable

Data: LV-coded data (and C-MAC if present)  
INSTALL[for LOAD]  
[len][Load File AID]
[len][ISD AID]                                   (CONDITIONAL)
[len][Load File Data Block Hash]                 (CONDITIONAL)
[len][Load Params] (see GP, clause 11.5.2.3.7)   (CONDITIONAL)
[len][Load Token]  (see GP, Appendix C.4.1)      (CONDITIONAL)
[C-MAC]

INSTALL[for install]
[len][Executable Load File AID]                  (CONDITIONAL)
[len]Executable Module AID]                      (CONDITIONAL)
[len][Applet AID]
[len][Privileges]     (see GP, clause 11.1.2)
[len][Install Params] (see GP, clause 11.5.2.3.7)
[len][Install Token]  (see GP, C.4.2 and C.4.7)  (CONDITIONAL)
[C-MAC]

INSTALL[for make selectable]
[00]
[00]
[len][Applet AID]
[len][Privileges] (see GP, clause 11.1.2 and 6.6)
[len][Make selectable params] (see GP, clause 11.5.2.3.7) (CONDITIONAL)
[len][make selectable token]  (see GP, C.4.3)    (CONDITIONAL)
[C-MAC]

```


### LOAD command (GP 2.3, clause 11.6)

Transmits the Load File (.cap file)

```shell
CLA: 80  
INS: E8  
P1: 00 - more blocks to be uploaded
    80 - last block
P2: sequential number of subsequent command

Data:
[C4][len][Load File Data Block 1] [C-MAC]
         [Load File Data Block 2] [C-MAC]
         ======//======
         [Load File Data Block n] [C-MAC]
```


### Using pycryptodome instead of cryptography library
The reason preferring former is because the latter doesn't support Single DES cipher which is required for establishing the SCP02.
