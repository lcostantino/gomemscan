# gomemscan


## Intro

GoMemScan is just a handy tool to scan process memory via Linux VM read syscalls introduced during 2019.

Even if /proc/X/mem is not accessible you may still have the CAPABILITY to read memory via this syscall. (as root or user)

The current implementation just looks for a byte pattern, but adding Yara for instance would be straightforward.

## Limitations

The current implementation is Linux based only, targeting kernels that support process_vm_readv, but OSX and Windows provide similar capabilities that may be added in the future.

* Only tested on amd64 

## Build

- This project use [GoReleaser](https://goreleaser.com/) to create proper artifacts and release control.
- A Makefile is provided just for dev purposes


## Usage

```
./gomemscan -h
```

| Arg        |  Details       | Default  |
| ------------- |-------------|----------|
| blen          | Chunk / Bucket size of memory where the patterns is going to search. (Memory will be split based on this size | 1048576 bytes |
| colors        | Disabled / Enable console colors | True |
| context-bytes | Bytes to print after/before the match as part of the context. (Ex: pepe in IamThePepeSapoEl with context 2 would output hepepesa )| 16 bytes |
| from         | Start address to scan if not using full scan | |
| fullscan     | Scan /proc/pid for maps and scan every readeable section | |
| go-routines   | Change number of go-routines used while scanning. It's just for playing :) | 16 |
| justmatch     | If enabled memory won't be kept until results are processed. Usefully for initial inspection when results are not needed| false |
| length        | Bytes to read: when using from argument for manual scan, this arg would determine the end addr ||
| mapperm       | When fullscan enabled, it's possible to filter maps based on permissions. Ex: 4 Read, 2: Write, 1: Exec, 0: Any|0|
| matches       | Maximum number of matches per chunk/bucket. Usually lot of matches will be present for the same string | 10 |
| output        | Save json results to provided file. If RAW argument is enabled this will be used as prefix for data dump ||\
| pattern       | Pattern to look for. Syntax is re2 (bytes/string/etc) ||
| pid           | Target Pid ||
| print-output  | Dump output to terminal | true |
| raw-dump      | For each matched chunk/bucket of blen size save it to disk for later analysis||
| stop-first-match | One 1 ore more matches for the same chunk is found, stop scanning ||
| verbose       | Enable versbose output | false |


* Return code will always be 0 if there's at least one match

## Sample (test)

In this test sample, there's a dummy malware that just sleeps and has some reference to onedrive folder.
```
#include <stdio.h>

int main(int argc, char *argv[])
{
    char *mypass = "onedrive";
    printf("%d\n", getpid());
	while(1) { sleep(10); }
}
```

Running pid: 3863, let's trigger this tool to scan for "oned" pattern in any map sections. 


```
./gomemscan  -pid 3863 -fullscan -pattern "\x6f\x6e\x65\x64" -mapperm 0 

or 

./gomemscan  -pid 3863 -fullscan -pattern "oned" -mapperm 0 

---- [ GoMemScan Ver:  ] ----

{
	"Bsize": 1048576,
	"Pid": 3863,
	"ImageName": "/home/obelisco/a",
	"Matches": [
		{
			"Chunk": "AQACAG9uZWRyaXZlACVkCgAAAAABGwM7",
			"Location": {
				"Start": 94586825945092,
				"End": 94586825945096
			},
			"Name": "/home/obelisco/a"
		},
		{
			"Chunk": "AQACAG9uZWRyaXZlACVkCgAAAAABGwM7",
			"Location": {
				"Start": 94586825940996,
				"End": 94586825941000
			},
			"Name": "/home/obelisco/a"
		}
	]
}

```

For every chunk start, end, location (if available), and data with context bytes will output based on passed arguments.
Inspecting both matches we clearly see:

```
> echo AQACAG9uZWRyaXZlACVkCgAAAAABGwM7|base64 -d
onedrive%d

```

# Sample Test Demo 



## Search for bytes / strings in a firefox instance stopping after the first chunk match. (Ex: Cabalango city search and CryptoMiner related wallet number) 

![](/docs/rsa.gif)

# Notes

When saving context and raw data export be careful with memory. If there a pattern that will match always it will grow to keep data
in memory until results are processed.

The same applies when using a .* regex, since the context is after/before the entire match, so results could be bigger than expected.

There are alternatives like --justMatch to reduce the overhead in case you only want to know if there's a match or not.

Even that coroutines could be expanded it would be wise to change bulk length appropriately since at the end of the day they rely on the syscall read.

# Todo

1. JS embed to show results
2. Yara?
