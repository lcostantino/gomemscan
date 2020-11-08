# gomemscan


## Intro

GoMemScan is just a handy tool to excersie Linux VM read syscalls introduced during 2019 plus my GO learning.

Even if /proc/X/mem is not accessible you may still have the CAPABILITY to read memory via this syscall. (sometimes as user for your own apps or as root)

The current implementation just look for a byte pattern, but adding Yara for instance would be straighfoward.


## Limitations

Current implemntation is Linux based only, targeting kernels with support for THIS SYSCALL, but OSX and Windows providers similar capabilities that may be added in the future.

* Only tested 64 bits


## Usage

```

Usage of ./gomemscan:
  -blen uint
    	Bucket size where the pattern is applied (default 1048576)
  -colors
    	enable or disable colors (default true)
  -context-bytes int
    	Bytes to print after and before a match (default 16)
  -from uint
    	Start address (0x4444444)
  -fullscan
    	Scan all mapped sections
  -go-routines int
    	Go routines to use during scanning (default 6)
  -justmatch
    	If enabled memory won't be held nor raw data will be availble. Usefully just for initial inspection (match or not)
  -length uint
    	Bytes to read (default 1048576)
  -mapperm int
    	When scanning mapped sections filter those that match specific permission bit(ex: 4 for read). 0 to ignore it
  -matches int
    	Max matches per chunk (default 10)
  -output string
    	Output file name. It will be used as prefix for raw output if selected
  -pattern string
    	(*required if patternString not provided) Bytes Pattern to match Ex: \x41\x41 - Warning: a match all pattern will hold all the chunks in memory!
  -pid int
    	(*required) Pid to read memory from
  -print-output
    	Print json output if file not provided (default true)
  -raw-dump
    	Generate a file per chunk that matched with binary data
  -stop-first-match
    	Stop after the first chunk match
  -string string
    	Convert the string to bytes pattern - Use pattern for regex match
  -verbose
    	Verbose

```



* Result will always be 0 if there's at least one match

## Sample (test)

In this test sample, there's a dummy malware that just sleep and have some reference to a onedrive folder.
```
#include <stdio.h>

int main(int argc, char *argv[])
{
char *mypass = "onedrive";
printf("%d\n", getpid());
	while(1) { sleep(10); }
}
```

Running pid: 3863, let's trigger this tool to scan for "oned" pattern in all maps sections.

```
./gomemscan  -pid 3863 -fullscan -pattern "\x6f\x6e\x65\x64" -mapperm 0 
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

For every chunk start , end , location (if available) and data with context bytes will output based on passed arguments.
Inspecting both matches we clearly see:
```
> echo AQACAG9uZWRyaXZlACVkCgAAAAABGwM7|base64 -d
onedrive%d

```

# Sample Test Demo 


## Search in a firefox instance a string in memory and stop after the first chunk match.
### The string argument will convert each character to \x[HEX] rep to build the same string as required by pattern.

```
./gomemscan  -fullscan -string cabalango.gob  -pid 0000   -stop-first-match 
```


# Notes

When saving context and raw data export be carefully with memory. If there a pattern that will match always it will growth to keep data
in memory until resuts are processed.

There are alternatives like --justMatch to reduce the overhead in case you only want to know if there's a match or not.

Even that coroutines could be expanded actually it would be wise to change bulk length aproppiately since at the end of the day they relly on the syscall read.
# Todo

1. JS embed to show results
2. Yara?