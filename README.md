# Description
miniDumpReader is a Windows MiniDump (MDMP) reader that leverages Kaitai Struct (https://kaitai.io) to parse Windows memory dumps.


## Requirements
```
python3 -m pip install kataistruct
```

## Usage
```
──(parallels㉿kali-linux)-[~/Tools/miniDumpReader]
└─$ python3 dmpStruct.py -h                                               
usage: dmpStruct.py [-h] [-f FILE] [-X] [-y YARA]

[*] Usage: dmpStruct.py -f <*.dmp>

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Provide a DMP file (minidump)
  -X, --hex             Writing data in hex into memoryStrings.txt
  -y YARA, --yara YARA  Yara rule(s) directory or file.
```

The results are saved automatically to `memoryStrings.txt`

```
# Scan DMP with Yara
python3 dmpStruct.py -f /home/parallels/Tools/miniDumpReader/rev_http.dmp -y /home/parallels/Tools/miniDumpReader/Yara/rules
```
```
# Writing Hex strings to memoryStrings.txt
python3 dmpStruct.py -f /home/parallels/Tools/miniDumpReader/rev_http.dmp -y /home/parallels/Tools/miniDumpReader/Yara/rules -X
python3 dmpStruct.py -f /home/parallels/Tools/miniDumpReader/rev_http.dmp -X
```
