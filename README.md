# idaflirt-detector
idaflirt-detector is Python scripts and IDA FLIRT signatures to detect statically linked libraries from stripped ELF file.
## Script
There are scripts in "script" directory.
### pkg2sig.py
- OS  
UNIX-like OS
- ENvironment  
Python 3
- Child Process  
wget、tar  
Same directory as the script : flair??\bin\linux\pelf, flair??\bin\linux\sigmake
- Output  
Same directory as the script : pkg, lib, pat, sig, name_alternate.csv, name_ignore.txt

When "pkg2sig.py" is executed, it creates directories named "pkg", "lib", "pat" and "sig" in the same directory as the script.
It also creates a working directory named "tmp", which it deletes on exit.
It will also create a working directory named tmp, which will be deleted on exit.
(If there is already "tmp", the existing "tmp" is also deleted.)
And it is assumed that "flair??\bin\linux\pelf" and "flair??\bin\linux\sigmake" are existing in the same directory as the script.

It calls "wget" to download the distribution's packages into "pkg" directory.
The subdirectory and url of the package to download are hard-coded into the script.
The subdirectory is the name and version number of the distribution.
The saved file name is determined by the url.

It extracts the downloaded package to "tmp" directory and saves "libc.a" and "libgcc.a" renamed to "lib" directory.
The names are hard-coded into the script based on the name and version number of the distribution and prepends "_libc_" or "_libgcc_".
The subdirectories correspond to the architecture name of IDA Pro.
If a package contains more than one libc.a or libgcc.a, the name is appended with the directory name which is contained in the package.

It calls "pelf" to convert the files in "lib" with the extension ".a" into pattern files.
The pattern files are stored in "pat", which has the same base name as the library and with ".pat" extension.
The subdirectories are the same as in "lib" above.
If the same pattern file is created, it is ignored and its contents is the first pattern file name.

It calls "sigmake" to convert pattern files into signature files.
The signature files are stored in "sig", which has the same base name as the library and with ".sig" extension.
The subdirectories are the same as in "pkg" or "lib" above.
If they are copied to the IDA Pro sig folder (usually "%ProgramFiles%\IDA Pro ?.?\sig"), they are used as a signature on IDA Pro.

It creats "name_alternate.csv" if it does not exist in the directory in the same directory as the script.
It creats "name_ignore.txt" if it does not exist in the directory in the same directory as the script.
### chksig.py
- OS  
Windows
- Environment  
Python 3(IDA Python)
- Input  
Same path as the sample : *_chksig.json  
IDA Pro：*.sig
- Output  
Same path as the sample : *_chksig.json

The script is executable on command line and IDA Python.
#### Command Line
The ELF file is specified as an argument on the command line.
The script executes IDA Pro and itself as IDA Python.
It will repeat executing IDA Python until it either detects statically linked library or determines that there is no statically linked library.
It is assumed that IDA Pro is installed in "%ProgramFiles%\IDA Pro*".
##### Option
- -f、--force  
Delete JSON if it is existing.
- -i、--ignore  
--ignore-entropy, --ignore-machine and --ignore-strip is enabled.
- --ignore-entropy  
Without this option, files with an overall entropy of less than 7.2 are targeted.
With this option, all files are targeted, regardless of their entropy.
- --ignore-machine  
Without this option, files with CPU of ARM, MIPS, Renesas SH, PowerPC or cisco 4500, x86-64 or Intel 80386 are targeted.
With this option, all files are targeted.

- --ignore-strip  
Without this option, files with statically linked and stripped are targeted.
With this option, all files are targeted, regardless of linked or stripped.
#### IDA Python
If JSON file with the same base name and the name ending in "_chksig.json" is not existing, "chksig.py" applies all the signatures and writes the number of detected functions in each signature to the JSON file.
It reads the JSON file if it exists.
It applies the signature the greatest estimate value and no determine value in JSON, and writes the number of detected functions in the signature to the JSON file as the determine value.

If the determine value is greater than the other values of estimate and determine, then its library is considered to be statically linked.
### prepare.py
- OS  
Windows
- Environment  
Python 3(IDA Python)
- Input  
Same path as the IDB : *_chksig.json  
IDA Pro：*.sig  
Same path as the script : prepare.txt, name_alternate.csv

"prepare.py" calls the following functions.
It parse the "prepare.txt" which is specified as an argument on the command line and output the sorted results.
#### functionalize_single_instruction()
The function scans all the addresses, and if there is an area of code which does not belong to a function, it makes that area into a single function.
#### apply_signature()
The function reads the file with the same base name the IDB and the name ending in "_chksig.json".
This JSON is a dictionary and it applies the signature indicated by the key "result" value.
#### true_up_function_name()
The function reads "name_alternate.csv" in the same directory as the script.
Based on this file, the names of the functions are normalized. It also sets the flags of the library function.
#### get_c_main()
The function returns the address of the function whose name is "main" or "main_<hexadecimal address>", if it is found.
If there is no such function, it returns BADADDR.
If there are more than one function, the behaviour is undefined.
#### register_c_main()
If get_c_main returns BADADDR, the function estimates the C main function and defines that function.
If there is only one function which is no name and refered as data from the entry point, the function is estimated to be main.
The detection of main fails if there is no corresponding function or if there are multiple functions.
The function changes the name of the detected function to "main_<hexadecimal address>".
#### load_type_library()
The function loads the type library "gnuunx64" if 64-bit, and "gnuunx" otherwise.
#### apply_function_type()
The function reads "prepare.txt" in the same directory as the script.
Based on this file, the function applies the function declaration if the names are matched.
If the function can read "name_alternate.csv" in the same directory as the script, non-normalized names are supported based on the file.
## File Format
### *_chksig.json
The file is JSON and the content is dictironay.
The keys are "estimate", "determine" and "result".
"estimate" and "determine" are dictionary, the key is the signature name, the value is the number of detected functions.
"estimate" is the number when all the signatures are applied at the first time, and "determine" is the number when the signature is applied independently.
"result" is dictionary, the key is the prefix of the signature name, the value is the signature name.
If "result" is existing, the identification has been completed.
## Deliverable
The deliverables are the files generated as a result of executing the script and they are in "deliverable" folder.
### name_alternate.csv
If the same function has more than one name, the names of the functions are output on a single line, separated by a ",".
Each line is sorted in order of shortest name and lexical order.
In this study, the first name is regarded as the normalized name of the function.
### name_ignore.txt
Each line is the function names in "libgcc.a".
### sig/{arm,mc68k,mips,pc,ppc,sh3}
If they are copied to the IDA Pro sig folder (usually "%ProgramFiles%\IDA Pro ?.?\sig"), they are used as a signature on IDA Pro.
## Copyright
Copyright (c) 2022 SecureBrain.
## Acknowledgment
This research was conducted under a contract of "MITIGATE" among "Research and Development for Expansion of Radio Wave Resources(JPJ000254)", which was supported by the Ministry of Internal Affairs and Communications, Japan.
