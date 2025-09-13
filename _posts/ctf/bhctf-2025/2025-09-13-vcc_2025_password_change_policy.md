---
title: Vehicle Cybersecurity Competition CTF 2025 Tasks - Password Change Policy
date: 2025-09-13 17:27:09 +0200
categories:
  - CTF
  - BHCTF-2025
  - VCC-2025
tags:
  - ctf
  - ctf-automotive
  - ctf-reverse
description: My solution for Password Change Policy challenge from Vehicle Cybersecurity Competition (VCC) 2025
mermaid: true
---
# Intro

This September I took part in BlockHarbor & Vehicle Cybersecurity Competition CTF. Overall, there were 8 tasks split into 2 categories - `Blue Team` and `Red Team`.

In this post, I'm sharing my solution for `Password Change Policy` task from `Red Team` category, for a curious soul to check and compare with their approach.
# The task
This challenge dives into Universal Diagnostic Services (UDS) and firmware reverse engineering. You'll need to reconstruct a complete firmware image from a raw CAN log file.

The main goal is to identify and understand a new Security Access algorithm embedded within the firmware. This algorithm is common to other automotive security access algorithms, requiring meticulous binary analysis to extract.  Success hinges on your UDS knowledge and reverse engineering skills.

Prompt: 
```
I updated my RAMN with a new firmware for ECU C, but it seems like the Security Access algorithm has been 
updated and I can’t unlock it anymore.

ECU C just gave me the seed: 9A5ABF0C1CAAFDEB72761E909501D6E9.

What is the answer to that seed? (Note: flag is 32-character hexadecimal string, all caps).
```

## Attachments

[CAN traffic log](/assets/files/bhctf-2025/challenge3.tar.xz)

# Solution
Based on task description, we are given a can traffic log containing ECU firmware update via UDS over CAN. Our goal is to extract the firmware from the can traffic log, reverse engineer it, find a new UDS authentication routine, and understand what key corresponds to the seed `9A5ABF0C1CAAFDEB72761E909501D6E9`.

Let's start from CAN traffic analysis. Once we get to the point where knowledge of UDS protocol is required, we will have a recap of it.
## CAN traffic log analysis
The CAN traffic log file `challenge3.log` is a text file that can simply be opened and analysed in any text editor.  Also `wireshark` can open CAN traffic logs. To solve this challenge, I decided to use another great tool - [`Savvy CAN`](https://github.com/collin80/SavvyCAN). It's a GUI tool that can assist with CAN traffic analysis a lot.
Once we open the traffic log in `Savvy CAN`, we will see the traffic list and some statistics:
![Savvy CAN main window](/assets/files/bhctf-2025/img.png)
A good idea is to search for UDS traffic referred to in the task description. For that we can use 
`RE Tools -> ISO-TP Decoder`, since UDS communications use ISO-TP as a transport layer taking care of UDS message payload fragmentation and frame sequencing.

We can observe popped up ISO-TP message list and easily filter out irrelevant CAN IDs `0x039`, `0x150`, and `0x1B8`, as their `Data` sections do not contain actual UDS data. This will leave us with 2 CAN IDs: `0x7E2` and `0x7EA`. Don't forget to press `Interpret Previously Captured Frames` after you uncheck irrelevant CAN IDs:
![`ISO-TP Decoder window`](/assets/files/bhctf-2025/img2.png)
Now we can browse through each remaining packet in the list and see UDS decoding details in the bottom left corner of the window.

UDS communication starts from service `Tester present` with CAN ID `0x7E2` Thus, communication initiator (tester) uses CAN ID `0x7E2`, and ECU responses with `0x7EA`.

Before we dive into communication flow between the tester and the ECU, let's briefly observe the transport layer - ISO-TP, and refresh UDS protocol. If you are familiar with those protocols, jump straight to [[#UDS communication flow]].
### ISO-TP recap
A good overview of ISO-TP protocol is available on [Wikipedia](https://en.wikipedia.org/wiki/ISO_15765-2). Below are some key points important for further solution.

The ISO-TP defines four frame types:

| Type                    | PCI Code | Description                                                                                                                                               |
| ----------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Single frame (SF)       | 0        | Contains the complete payload of up to 7 bytes for normal CAN addressing.                                                                                 |
| First frame (FF)        | 1        | First frame of a multi-frame packet, used when data is longer than  7 bytes. The first frame contains the length of the full packet and the initial data. |
| Consecutive frame (CF)  | 2        | A frame containing subsequent data for a multi-frame packet                                                                                               |
| Flow control frame (FC) | 3        | Response from the receiver, acknowledging a start of a multi-frame packet. Used to manage the pace of the consecutive frames.                             |
The ISO-TP CAN packet therefore looks like this:

```
        ,------------------------------------------------------------------------------------.
 Byte   |       0      |    1    |    2    |    3    |    4    |    5    |    6    |    7    |
        |--------------|---------|---------|---------|---------|---------|---------|---------|
 Nibble | High  | Low  |         |         |         |         |         |         |         |
        |--------------|---------|---------|---------|---------|---------|---------|---------|
SF      |   0   | Len  | Data[0] | Data[1] | Data[2] | Data[3] | Data[4] | Data[5] | Data[6] |
        |       |(0-7) |         |         |         |         |         |         |         |
        |------------------------|---------|---------|---------|---------|---------|---------|
FF      |   1   |      Len       | Data[0] | Data[1] | Data[2] | Data[3] | Data[4] | Data[5] |
        |       |(0x008 - 0xFFF) |         |         |         |         |         |         |
        |------------------------|---------|---------|---------|---------|---------|---------|
CF      |   2   |Index | Data[0] | Data[1] | Data[2] | Data[3] | Data[4] | Data[5] | Data[6] |
        |       | 0-15 |         |         |         |         |         |         |         |
        |------------------------|---------|---------|---------|---------|---------|---------|
FC      |   3   | Flag |Blk size | STmin   |         |         |         |         |         |
        `------------------------------------------------------------------------------------'
```

We don't care much about `FC` (flow control) frame type and it's fields. Of a primary interest for us are `SF` used for short data transmission (up to 7 bytes), `FF` (first frame in a sequence of frames transmitting more than 7 bytes of data), and `CF` - consecutive frames in a long data sequence.
Example ISO-TP CAN frame:
```
7E2#023E00
|- 7E2 - CAN ID
|- 0 - SF frame 
|- 2 - length 0x02 bytes
|- 3E00 - payload
```

Another example:
```
7E2#100B340044080000
|- 1 - FF frame
|- 00B - payload length
|- 340044080000 - first 6 bytes of payload

7EA#300000
|- 3 - FC frame
|- 00000 - FC parameters we don't care much about in this writeup

7E2#21000001B900
|- 2 - CF frame
|- 1 - index of the payload block
|- 000001B900 - last 5 bytes of payload
```
### UDS recap

UDS (ISO 14229) is an application-level protocol that uses ISO-TP for transport. A good overview of Unified Diagnostic Services protocol can be found [here](https://www.csselectronics.com/pages/uds-protocol-tutorial-unified-diagnostic-services). I'll highlight some important take-aways.

UDS requests are sent from tester to ECU, and ECU answers with UDS response.

UDS request has the following format:
```
   Byte 0     Byte 1      Byte 2 ...  
+----------+-----------+-----------+-----------+
|    SID   | PAYLOAD                           |
+----------+-----------+-----------+-----------+
```

`SID` is the service ID byte identifying command. Depending on a specific service ID, payload format varies. Request payload can contain sub-function code, parameters, and so on.
In case of successful command execution ECU responds:
```
   Byte 0     Byte 1      Byte 2 ...  
+----------+-----------+-----------+-----------+
| SID+0x40 | PAYLOAD                           |
+----------+-----------+-----------+-----------+
```
The response SID is an original `SID + 0x40`.
In case of an error, negative response is sent:
```
  Byte 0    Byte 1  Byte 2 
+--------+--------+--------+
|  0x7F  |   SID  |   NRC  |
+--------+--------+--------+
```
Negative response code NRC is an error code that allows to understand what went wrong.
`SID`, `NRC` values, and command formats for each `SID` can be easily found in the article linked above.
#### UDS Security Access
One particular command we will need is `SID=0x27` - `Security Access`. It's used for authentication and works in several steps:
```
     +---------+                               +----------+
     | Tester  |                               |   ECU    |
     +---------+                               +----------+

         |                                          |
         |------ Request Seed (0x27 0x02) --------->|
         |                                          |
         |<---- Response with Seed (0x67 0x02) -----|
         |          (e.g., SEED = 0x12 0x34)        |
         |                                          |
         |-- Calculate Key using proprietary algo --|  ← Local calculation on tester side
         |                                          |
         |------ Send Key (0x27 0x03 KEY...) ------>|
         |                                          |
         |<----- Positive Resp (0x67 0x03) ---------|  ← If key is valid
         |                                          |
         |         [OR]                             |
         |<----- Negative Resp (0x7F 0x27 NRC) -----|  ← If key is invalid
         |                                          |
```
### UDS communication flow
Having ISO-TP and UDS knowledge refreshed, let's go through the UDS communication flow between `0x7E2` and `0x7EA` that we have discovered with `SavvyCAN`. We can filter out other CAN IDs by, for example, a regexp, or with a simple python script.

To decode a specific UDS message, you can either Google the request format by SID or use `SavvyCAN` and it's embedded UDS decoder for ISO-TP frames.

```bash
# UDS SID = 0x3E - Tester Present, positive response from the ECU
(1752232981.854494) can0 7E2#023E00
(1752232981.854494) can0 7EA#027E00

# UDS service 0x10 - Diagnostic Session Control
(1752232981.859488) can0 7E2#021002
(1752232981.859488) can0 7EA#025002

# Security access (authentication)
(1752232981.860684) can0 7E2#022701
(1752232981.860684) can0 7EA#066701BC96C932
(1752232981.864425) can0 7E2#062702AEA29F4A
(1752232981.864426) can0 7EA#026702

# Routine control, start routine 0200
(1752232981.866349) can0 7E2#0431010200
(1752232981.866349) can0 7EA#0471010200

# Routine control - erase memory routine
(1752232981.869908) can0 7E2#043101FF00
(1752232984.684915) can0 7EA#047101FF00

# 34 00 44 08 00 00 00 00 01 B9 00
# Request Download to mem address 0x44080000 size 0x0001B900
(1752232984.742587) can0 7E2#100B340044080000
(1752232984.742587) can0 7EA#300000
(1752232984.744224) can0 7E2#21000001B900
(1752232984.744224) can0 7EA#0474200FF0

# Transfer Data block 01 with size (0xFFA - 2)
(1752232984.746379) can0 7E2#1FFA360100000420
(1752232984.746380) can0 7EA#300000
(1752232984.749593) can0 7E2#21AD780008DD7500
...
# Finish Transfer Data block 01
(1752232985.002683) can0 7E2#2893594B
(1752232985.050116) can0 7EA#027601
...
# Transfer Data block 02 with size (0xFFA - 2)
(1752232985.054981) can0 7E2#1FFA3602574905F0
(1752232985.054982) can0 7EA#300000
(1752232985.057378) can0 7E2#2115FC7B89002B3A
...
# Finish Transfer Data block 02
(1752232985.312676) can0 7E2#28220008
(1752232985.359828) can0 7EA#027602
...

# Transfer Data block 0x1C with size (0x9DA - 2)
(1752232993.125367) can0 7E2#19DA361C00000000
(1752232993.125368) can0 7EA#300000
(1752232993.127663) can0 7E2#2100000000000400

# Finish Transfer Data block 0x1C
(1752232993.282278) can0 7E2#28A90008
(1752232993.315463) can0 7EA#02761C

# Stop data transfer
(1752232993.317617) can0 7E2#0137
(1752232993.317618) can0 7EA#0177

# Call a service routine 0x0202
(1752232993.322653) can0 7E2#0431010202
(1752232993.326220) can0 7EA#0471010202

# Call a service routine 0xFF01
(1752232993.329218) can0 7E2#043101FF01
```
As stated in task description, the tester flashes the ECU with new software. We just need to iterate through all `Transfer Data Block` commands and assemble the payloads together in a single firmware file. Remember that to calculate each data block length, we need to subtract 2 bytes from ISO-TP FF frame length, because first 2 bytes are actually UDS `SID = 0x36` and parameter - block number (1 byte).

`SavvyCAN` can export ISO-TP decoded traffic to make the extraction task easier, but it was [buggy](https://github.com/collin80/SavvyCAN/issues/966) at the time I was writing this. So I wrote Python script that extracts firmware from the log to the binary file:
```python
from binascii import hexlify, unhexlify

# First, remove all CAN noise. Leave only Traffic between CAN IDs 0x7E2 and 0x7EA
dump_lines = open("challenge3.log", "r").read().split("\n")
uds_list = []
for line in dump_lines:
    if ("7E2#" in line) or ("7EA#" in line):
        uds_list.append(line)

of = open("firmware.bin", "wb")

i = 0

# Now iterate through ISO-TP
while i < len(uds_list):
    # Skip empty lines if any in uds_list
    if not uds_list[i]:
        i += 1
        continue
    # Get packet payload
    cur_payload = unhexlify(uds_list[i].split("#")[1])
    # This check is true for ISO-TP FF frames with UDS SID = 0x36 - Transfer Data Block.
    if (cur_payload[0] & 0xF0 == 0x10) and (cur_payload[2] == 0x36):
        # We found start of data block
        block_data = b""
        # Extract block number, length, and first bytes of payload from the initial ISO-TP FF frame
        block_len = ((cur_payload[0] & 0x0F) << 8) + cur_payload[1]
        block_num = cur_payload[3]
        block_data += cur_payload[4:]
        remain_bytes = block_len - len(block_data) - 2
        # Every ISO-TP SF frame contains 7 bytes of block data
        remain_packets = remain_bytes // 7
        # The last ISO-TP block frame may contain less than 7 bytes of data
        tail = remain_bytes % 7
        print(f"Found firmware block {hex(block_num)}; len = {hex(block_len)} ")
        j = 0
        i += 2 # Skip current frame and next FC frame from the ECU
        while j < remain_packets:
            if not "7E2#" in uds_list[i + j]:
                print(f"Error in packet {uds_list[i + j]}")
                exit(1)
            cur_payload = unhexlify(uds_list[i + j].split("#")[1])
            block_data += cur_payload[1:]
            j += 1
        i += remain_packets
        if tail:
            cur_payload = unhexlify(uds_list[i].split("#")[1])
            block_data += cur_payload[1:1+tail]
            i += 1
        of.write(block_data)
    else:
        # This frame is not start of transfer block. Skip it
        i += 1
```

The script output and result file size & MD5 sum:
```bash
➜  password_change_policy python3 parse_dump.py                        
Found firmware block 0x1; len = 0xffa
Found firmware block 0x2; len = 0xffa
Found firmware block 0x3; len = 0xffa
Found firmware block 0x4; len = 0xffa
Found firmware block 0x5; len = 0xffa
Found firmware block 0x6; len = 0xffa
Found firmware block 0x7; len = 0xffa
Found firmware block 0x8; len = 0xffa
Found firmware block 0x9; len = 0xffa
Found firmware block 0xa; len = 0xffa
Found firmware block 0xb; len = 0xffa
Found firmware block 0xc; len = 0xffa
Found firmware block 0xd; len = 0xffa
Found firmware block 0xe; len = 0xffa
Found firmware block 0xf; len = 0xffa
Found firmware block 0x10; len = 0xffa
Found firmware block 0x11; len = 0xffa
Found firmware block 0x12; len = 0xffa
Found firmware block 0x13; len = 0xffa
Found firmware block 0x14; len = 0xffa
Found firmware block 0x15; len = 0xffa
Found firmware block 0x16; len = 0xffa
Found firmware block 0x17; len = 0xffa
Found firmware block 0x18; len = 0xffa
Found firmware block 0x19; len = 0xffa
Found firmware block 0x1a; len = 0xffa
Found firmware block 0x1b; len = 0xffa
Found firmware block 0x1c; len = 0x9da
                                                           
➜  password_change_policy ls -la firmware.bin            
-rw-rw-r-- 1 dp dp 112896 Sep 13 16:28 firmware.bin              
➜  password_change_policy md5sum firmware.bin        
39ca6c6431c8003aa8d0d96988ec7f66  firmware.bin
```
Note that file size `112896 = 0x1B900` which corresponds to the firmware size in `Request Download` UDS command.
## Firmware analysis
Now that we have a firmware file with correct size, we can load it into decompiler. We need to find a UDS `Security Access` command handler with `SID=0x27` and understand how it verifies keys, to be able to calculate a correct key for seed ``

### Detecting CPU architecture
A good first step (although not necessary in this particular case) is to try find CPU instructions and architecture. You can do that with `binwalk -A firmware.bin`, but for this case it didn't detect the architecture. Another approach is to run a nice tool by **Airbus seclab** called `cpu_rec` available on [GitHub](https://github.com/airbus-seclab/cpu_rec).
```bash
➜  password_change_policy python3  ~/tools/re/cpu_rec/cpu_rec.py ./firmware.bin
./firmware.bin full(0x1b900)  ARMhf  chunk(0x17400;93)   ARMhf
```
We are dealing with ARMhf, which stands for ARM with Hard Float.

### Loading binary to IDA
If you have IDA, you can drop the file to it and get a loader `cortex_m.py` ready to do CPU selection, memory segment mapping and code marking for you:
![[/assets/files/bhctf-2025/img3.png]]
That's why I told that CPU architecture recognition can be skipped this time.

If you have to load the binary manually, I remind that the loading address from UDS dump was  `0x44080000`. Select ARM little-endian as CPU architecture.

### Reverse engineering
The firmware is large, so analysis from reset vector and code start address will take a while. To shorten our path, we can review the list of strings and find some interesting ones:
```
Code:0801ACC0	00000010	C	RAMN_ReceiveUSB
Code:0801ACD0	00000010	C	RAMN_ReceiveCAN
Code:0801ACE0	0000000D	C	RAMN_SendCAN
Code:0801ACF0	0000000E	C	RAMN_Periodic
Code:0801AD00	0000000F	C	RAMN_ErrorTask
Code:0801AD10	0000000C	C	RAMN_DiagRX
Code:0801AD1C	0000000C	C	RAMN_DiagTX
Code:0801AD28	0000000D	C	RAMN_SendUSB
Code:0801AD38	0000000D	C	RAMN_RxTask2
Code:0801AD48	0000000D	C	RAMN_TxTask2
```
Following the link to `RAMN_DiagRX` string we can discover the function with the same name in the code. We than start it's brief analysis and quickly find function `sub_8006478` with a switch-case that looks like selection of a proper handler for each supported UDS SID:
```c
void __fastcall sub_8006478(int a1, char *req, unsigned __int16 reqLen, char *rsp, __int16 *pRspLen)
{
  UDS_RSP = rsp;
  pUDS_RSP_LEN = pRspLen;
  *pRspLen = 0;
  UDS_AUTH_CTX.field_4 = a1;
  if ( reqLen )
  {
    if ( (unsigned __int8)*req > 0xFu )
    {
      switch ( *req )
      {
        case 0x10:
          sub_8004428((int)req, reqLen);
          break;
        case 0x11:
          sub_8004544((int)req, reqLen);
          break;
        case 0x14:
          sub_80045B4(req, reqLen);
          break;
        case 0x19:
          sub_800461C(req, reqLen);
          break;
        case 0x22:
          sub_8004954(req, reqLen);
          break;
        case 0x23:
          sub_80047DC(req, reqLen);
          break;
        case 0x24:
          sub_8004BD8((int)req);
          break;
        case 0x27:
          uds_cmd_security_access(req, reqLen);
          break;
        case 0x28:
          sub_8004E22(req, reqLen);
          break;
   ...
}
```

The `uds_cmd_security_access` at address `08004DB8` looks as follows: 
```c
void __fastcall uds_cmd_security_access(char *req, unsigned __int16 reqLen)
{
  int sbf; // r3

  if ( reqLen <= 1u )
    goto LABEL_2;
  sbf = req[1] & 0x7F;
  if ( sbf == 1 )
  {
    uds_cmd_security_access_gen_seed(req, reqLen);
  }
  else if ( sbf == 2 )
  {
    if ( reqLen != 18 )
    {
LABEL_2:
      uds_rsp_error(req, INCORRECT_MSG_FORMAT);
      return;
    }
    uds_cmd_security_access_check_key(req);
  }
  else
  {
    uds_rsp_error(req, SUB_FUNC_NOT_SUPPORTED);
  }
}
```
Next, `uds_cmd_security_access_check_key` function at `0x8004CD4` after a bit of an analysis looks like this:
```c
void __fastcall uds_cmd_security_access_check_key(char *req)
{
  char rsp[4]; // [sp+Ch] [bp+Ch] BYREF
  int i; // [sp+10h] [bp+10h]
  char v3; // [sp+17h] [bp+17h]

  rsp[0] = 0x67;
  rsp[1] = req[1] & 0x7F;
  if ( UDS_AUTH_ATTEMPTS <= 4 )
  {
    if ( (unsigned int)(UDS_AUTH_CTX.field_4 - dword_20032B38) > 9 )
    {
      if ( byte_20032B40 == 1 )
      {
        v3 = 1;
        for ( i = 0; i <= 15; ++i )
        {
          if ( req[i + 2] != UDS_AUTH_CTX.key[i] )
            v3 = 0;
        }
        if ( v3 )
        {
          byte_20032B40 = 2;
          if ( req[1] >= 0 )
            uds_prepare_response(rsp, 2u);
        }
        else
        {
          byte_20032B40 = 0;
          ++UDS_AUTH_ATTEMPTS;
          dword_20032B38 = UDS_AUTH_CTX.field_4;
          uds_rsp_error(req, INVALID_KEY);
        }
      }
      else
      {
        uds_rsp_error(req, REQ_SEQUENCE_ERR);
      }
    }
    else
    {
      uds_rsp_error(req, REQUIRED_DELAY_NOT_EXPIRED);
    }
  }
  else
  {
    uds_rsp_error(req, ATTEMPTS_EXCEED);
  }
}
```

As we can see, it just verifies the key against some value in memory, stored inside `UDS_AUTH_CTX` structure with the following fileds:
```c
00000000 struct UDS_AUTH_CTX_STRUCT // sizeof=0x2C
00000000 {                                       // XREF: SRAM:UDS_AUTH_CTX/r
00000000     signed __int32 field_0;             // XREF: sub_80043AC+10/r
00000000                                         // sub_80043E8+C/w ...
00000004     signed __int32 field_4;             // XREF: sub_80043E8+24/w
00000004                                         // sub_8004428+3E/r ...
00000008     signed __int32 field_8;
0000000C     char seed[16];
0000001C     char key[16];
0000002C };
```

The structure is initialized once the seed is requested, in `uds_cmd_security_access_gen_seed` at `0x08004BF4`:
```c
void __fastcall uds_cmd_security_access_gen_seed(char *req, __int16 reqLen)
{
  _BYTE v2[2]; // [sp+0h] [bp+0h] BYREF
  __int16 v3; // [sp+2h] [bp+2h]
  char *v4; // [sp+4h] [bp+4h]
  char rsp[18]; // [sp+8h] [bp+8h] BYREF
  int k; // [sp+1Ch] [bp+1Ch]
  int j; // [sp+20h] [bp+20h]
  int i; // [sp+24h] [bp+24h]

  v4 = req;
  v3 = reqLen;
  *(_DWORD *)rsp = 103;
  memset(&rsp[4], 0, 14);
  rsp[1] = req[1] & 0x7F;
  for ( i = 0; i <= 15; ++i )
    UDS_AUTH_CTX.seed[i] = uds_security_access_gen_seed_byte();
  for ( j = 0; j <= 15; ++j )
    UDS_AUTH_CTX.key[j] = UDS_AUTH_SECRET[j] ^ UDS_AUTH_CTX.seed[j];
  for ( k = 0; k <= 15; ++k )
    v2[k + 10] = UDS_AUTH_CTX.seed[k];
  byte_20032B40 = 1;
  if ( v4[1] >= 0 )
    uds_prepare_response(rsp, 0x12u);
}
```

The key for each authentication attempt is calculated as `SEED XOR UDS_AUTH_SECRET`
Finally, static array  `UDS_AUTH_SECRET` holds the `XOR` key we need to apply to the seed to get the flag:
```c
Code:0801B358 UDS_AUTH_SECRET DCB 0x12, 0x33, 0x11, 0x33, 0x12, 0x33, 0x11, 0x33, 0x12 0x33, 0x11, 0x33, 0x12, 0x33, 0x11, 0x33
```
## The flag
We calculate the flag by `XOR`-ing two byte strings:
```
12331133123311331233113312331133 XOR 9A5ABF0C1CAAFDEB72761E909501D6E9 = 8869AE3F0E99ECD860450FA38732C7DA
```
Flag:
```
8869AE3F0E99ECD860450FA38732C7DA
```
