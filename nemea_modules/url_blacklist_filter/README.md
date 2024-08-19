# URL blacklist filter - NEMEA module

## Description

This modul recieves UniRec, checks if URL is on blacklist, if it is on blacklist, then it sends this UniRec to output. It requires file with blacklist as parameter.

### Input

Number of inputs: 1\
Description of input: The module receives UniRec data related to HTTP traffic. Required UniRec fields for this module are HTTP_REQUEST_HOST and HTTP_REQUEST_URL

### Output

Number of outputs: 1\
Description of output: Incoming UniRec data is sent to the output if the URL within the UniRec entry is found on a blacklist.

### Usage

url_detector [COMMON]... [OPTIONS]...
  
## Installation

1) Let Autotools process the configuration files.\
``` autoreconf -i ```

2) Configure the module directory.\
``` ./configure ```

3) Build the module.\
``` make ```

4) Install the module. The command should be performed as root (e.g. using sudo). \
``` make install ```

## Parameters of module [OPTIONS]

|Parameter|Description|
|---|---|
|-f  --file <char*>|Path to file with list of malicious URL addresses. Each line in the provided text file should contain a single URL.|

## Common TRAP parameters [COMMON]

|Parameter|Description|
|---|---|
|-h [trap,1]|If no argument, print this message. If "trap" or 1 is given, print TRAP help.|
|-i IFC_SPEC|Specification of interface types and their parameters, see "-h trap" (mandatory parameter).|
|-v|Be verbose.|
|-vv|Be more verbose.|
|-vvv|Be even more verbose.|

## 
