# gomemscan


## Intro

GoMemScan is just a handy tool to scan process memory via Linux VM read syscalls introduced during 2019.

- Even if /proc/X/mem is not accessible you may still have the CAPABILITY to read memory via this syscall. (as root or user)

Current version supports Windows too.

The current implementation supports regex patterns or yara rule file to scan the memory.

## Limitations

The current implementation supports Linux & Windows.
. For Linux: targeting kernels that support process_vm_readv

## Build

- This project use [GoReleaser](https://goreleaser.com/) to create proper artifacts and release control.
- Binaries with and without yara available at (https://github.com/lcostantino/gomemscan/releases/latest)

- The project can be built with static yara support or without it.
  - For yara (4.x) you will need:
     - Linux ARM64 (./configure --prefix=/usr/local/lib/armx64 --host=aarch64-linux-gnu) 
     - Linux AMD64
     - Win32 x64 (./configure --prefix=/usr/local/lib/winx64 --host=x86_64-w64-mingw32)

- Build with yara support (tag: yara)
 - ``` goreleaser  build -f .goreleaser-yara.yml  --skip-validate --rm-dist ```
- Build without yara support (no C no extra libs needed)
 - ```goreleaser  build -f .goreleaser.yml  --skip-validate --rm-dist```

## Usage

` It's important to add -fullscan unless the memory range to scane is known

```
./gomemscan -h
```

| Arg        |  Details       | Default  |
| ------------- |-------------|----------|
| all-pids	| Scan running processes| False|
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
| output        | Save json results to provided file. If RAW argument is enabled this will be used as prefix for data dump ||
| max-results   | Max results per scan|30|
| pattern       | Pattern to look for. Syntax is re2 (bytes/string/etc) ||
| pid           | Target Pid ||
| print-output  | Dump output to terminal | true |
| raw-dump      | For each matched chunk/bucket of blen size save it to disk for later analysis||
| stop-first-match | One 1 ore more matches for the same chunk is found, stop scanning ||
| verbose       | Enable versbose output | false |
| yara-file     | Use a yara rule file for matching. (Only if built with yara support)||


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

or 

./gomemscan-yara.exe  -pid 3863 -fullscan -yara-file myrule.yara

---- [ GoMemScan Ver:  ] ----

[{
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
}]

```

For every chunk start, end, location (if available), and data with context bytes will output based on passed arguments.
Inspecting both matches we clearly see:

```
> echo AQACAG9uZWRyaXZlACVkCgAAAAABGwM7|base64 -d
onedrive%d

```

# Sample Yara on AARCH64
```
root@debian:/tmp# uname -a; cat a.r;./gomemscan-yara  -pid 319 -yara-file a.r -fullscan |tee log

Linux debian 5.9.0-2-arm64 #1 SMP Debian 5.9.6-1 (2020-11-08) aarch64 GNU/Linux

rule DummyRule
{
    strings:
        $t = "192.168"
    condition:
        $t
}

---- [ GoMemScan Ver: 0.1.1-9a05019af3f6085af8c5d283f80fefcae823e920 ] ----

Scan time 693 ms
[{
	"Bsize": 1048576,
	"Pid": 319,
	"ImageName": "/usr/sbin/dhclient",
	"CmdLine": "/sbin/dhclient-4-v-i-pf/run/dhclient.enp1s0.pid-lf/var/lib/dhcp/dhclient.enp1s0.leases-I-df/var/lib/dhcp/dhclient6.enp1s0.leasesenp1s0",
	"Engine": "yara",
	"Matches": [
		{
			"Chunk": "AAAAAAAAAAAAAAAAAAAAADE5Mi4xNjguMTIyLjY3AAAAAAAAAAAA",
			"Location": {
				"Start": 187650348501840,
				"End": 187650348501847
			},
			"Name": "/usr/sbin/dhclient"
		},
		{
			"Chunk": "AAAAAAAAAGJvdW5kIHRvIDE5Mi4xNjguMTIyLjY3IC0tIHJlbmV3",
			"Location": {
				"Start": 187650348539369,
				"End": 187650348539376
			},
			"Name": ""
		},
		{
			"Chunk": "ICBmaXhlZC1hZGRyZXNzIDE5Mi4xNjguMTIyLjY3OwogIG9wdGlv",
			"Location": {
				"Start": 187650732878478,
				"End": 187650732878485
			},
			"Name": "[heap]"
		},
		{
			"Chunk": "IG9wdGlvbiByb3V0ZXJzIDE5Mi4xNjguMTIyLjE7CiAgb3B0aW9u",
			"Location": {
				"Start": 187650732878547,
				"End": 187650732878554
			},
			"Name": "[heap]"
		},
		{
			"Chunk": "aW4tbmFtZS1zZXJ2ZXJzIDE5Mi4xNjguMTIyLjE7CiAgb3B0aW9u",
			"Location": {
				"Start": 187650732878652,
				"End": 187650732878659
			},
			"Name": "[heap]"
		},
		{
			"Chunk": "cnZlci1pZGVudGlmaWVyIDE5Mi4xNjguMTIyLjE7CiAgb3B0aW9u",
			"Location": {
				"Start": 187650732878699,
				"End": 187650732878706
			},
			"Name": "[heap]"
		},
		{
			"Chunk": "b2FkY2FzdC1hZGRyZXNzIDE5Mi4xNjguMTIyLjI1NTsKICBvcHRp",
			"Location": {
				"Start": 187650732878774,
				"End": 187650732878781
			},
			"Name": "[heap]"
		},
		{
			"Chunk": "XTogREhDUE9GRkVSIG9mIDE5Mi4xNjguMTIyLjY3IGZyb20gMTky",
			"Location": {
				"Start": 281472963449440,
				"End": 281472963449447
			},
			"Name": ""
		},
		{
			"Chunk": "MTY4LjEyMi42NyBmcm9tIDE5Mi4xNjguMTIyLjEAAAAAAAAAdQAA",
			"Location": {
				"Start": 281472963449460,
				"End": 281472963449467
			},
			"Name": ""
		},
		{
			"Chunk": "REhDUFJFUVVFU1QgZm9yIDE5Mi4xNjguMTIyLjY3IG9uIGVucDFz",
			"Location": {
				"Start": 281472963450579,
				"End": 281472963450586
			},
			"Name": ""
		},
		{
			"Chunk": "MTldOiBESENQQUNLIG9mIDE5Mi4xNjguMTIyLjY3IGZyb20gMTky",
			"Location": {
				"Start": 281472963451182,
				"End": 281472963451189
			},
			"Name": ""
		},
		{
			"Chunk": "MTY4LjEyMi42NyBmcm9tIDE5Mi4xNjguMTIyLjEAAAAAAAAAAACV",
			"Location": {
				"Start": 281472963451202,
				"End": 281472963451209
			},
			"Name": ""
		},
		{
			"Chunk": "X25ldHf/////bnVtYmVyPTE5Mi4xNjguMTIyLjBw0GyQ//8AAAAA",
			"Location": {
				"Start": 281472963451707,
				"End": 281472963451714
			},
			"Name": ""
		},
		{
			"Chunk": "YAEAiP//AABgAQCI//8AADE5Mi4xNjguMTIyLjEAAAAQAgAAAAAA",
			"Location": {
				"Start": 281472963452000,
				"End": 281472963452007
			},
			"Name": ""
		},
		{
			"Chunk": "cnZlcl9pZGVudGlmaWVyPTE5Mi4xNjguMTIyLjFQAgAAAAAAAEQA",
			"Location": {
				"Start": 281472963452067,
				"End": 281472963452074
			},
			"Name": ""
		},
		{
			"Chunk": "b2FkY2FzdF9hZGRyZXNzPTE5Mi4xNjguMTIyLjI1NQAAAPAAAAAA",
			"Location": {
				"Start": 281472963452190,
				"End": 281472963452197
			},
			"Name": ""
		},
		{
			"Chunk": "WzMxOV06IGJvdW5kIHRvIDE5Mi4xNjguMTIyLjY3IC0tIHJlbmV3",
			"Location": {
				"Start": 281472963453452,
				"End": 281472963453459
			},
			"Name": ""
		},
		{
			"Chunk": "AAAAAAAAAAAAAAAAAAAAADE5Mi4xNjguMTIyLjY3AAAAAAAAAAAA",
			"Location": {
				"Start": 281473099917648,
				"End": 281473099917655
			},
			"Name": ""
		}
	]
}]
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

If you are looking for a project that includes UI, server and it's more featured check [Kraken](https://github.com/botherder/kraken)

