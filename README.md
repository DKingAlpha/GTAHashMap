# GTAHashMap
GTAHashMap dumped from Alexander Blade's ScriptHookV.dll

# Reversing
```
IDA: nativeInit(int64 a1):
    arg a1 is oldHash
    switch(gameVersion_dw)
    0x18D2 is hashinfo count
    unk/qword referenced by jump table case 2,3 is hashtable
```

```c
struct hashinfo {
    uint64_t   oldHash;
    uint64_t   hash[24];
};

struct hashtable {
    hashinfo[0x18D2];
};

```

Hash searching algorithm (reversed. seems like unfolded):
```c

// equivalant structure:  uint64_t hashtable[0x1884][22];

switch(gameVersion) {

    // omit break; each case actually breaks;

    case 0,1:
        newHash = oldHash;
    
    case 2,3:   // to 1
        newHash = hashtable[x][1]  where hashtable[x][0] == oldHash (or  newHash = oldHash if x not found)

    case 4,5:   // to 2
        newHash = hashtable[x][1]  where hashtable[x][0] == oldHash (or  newHash = oldHash if x not found)
        newHash = hashtable[x][2]  where hashtable[x][1] == newHash (or  newHash = oldHash if x not found) // re-search

    case 6,7,8,9:   // 3
        newHash = hashtable[x][1]  where hashtable[x][0] == oldHash (or  newHash = oldHash if x not found)
        newHash = hashtable[x][2]  where hashtable[x][1] == newHash (or  newHash = oldHash if x not found) // re-search
        newHash = hashtable[x][3]  where hashtable[x][2] == newHash (or  newHash = oldHash if x not found) // re-search

    case 10,11:
        ... 4
    
    case 12,13:
        ... 5
    
    14,15       6
    16,17       7
    18,19       8
    20,21,22,23 9
    24,25       10
    26,27       11
    28,29       12
    30,31,32,33 13
    34,35       14
    36,37       15
    38,39       16
    40,41       17
    42,43,44,45     18
    46,47,48,49     19
    50,51,52,53     20
    54,55,56,57,58      21
    59,60,61,62,63      22
    64,65,66,67,68      23

}
```

Optimized
```c
static int searchDepth = 24; /* 0 to 24 */
uint64_t newHash = oldHash;
for (int i = 0; i < fullHashMapCount; i++) {
    bool found = false;
    for (int j = 0; j < searchDepth; j++) {
        if (fullHashMap[i][j] == newHash) {
            found = true;
            if (fullHashMap[i][j + 1])
                newHash = fullHashMap[i][j + 1];
        }
    }
    if (found) break;
}
```

# Dumping
```python
from idaapi import *
import json

g_hashtable = 0x18002D730
g_hashinfo_count = 0x18D2
g_hash_count = 24

def ReadHashInfo(ea, hash_count):
    return [get_64bit(ea + i*8) for i in range(0, hash_count) ]

def ReadHashTable(ea, hashinfo_count, hash_count):
    return [ReadHashInfo(ea + i*8*hash_count, hash_count) for i in range(0, hashinfo_count)]

hashtable = ReadHashTable(g_hashtable, g_hashinfo_count, g_hash_count)

with open('D:/hashmap.h', 'w') as outfile:
    content = '''
#pragma once
#include <stdint.h>

#define fullHashMapCount %d
#define fullHashMapDepth %d

uint64_t fullHashMap[fullHashMapCount][fullHashMapDepth] = {
''' % (g_hashinfo_count, g_hash_count)
    for h in hashtable:
        item = '    {'
        for hi in h:
            item += "0x%X, " % hi
        item = item[:-2] + '},\n'
        content += item
    content = content[:-2]
    content += '\n};\n\n'
    outfile.write(content)

```


```python
from idaapi import *
import json

# qword_18002AE20 in worldGetAllPickups has max offset 
# __int64 __fastcall worldGetAllPickups(int *a1, int a2)
# {
# // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]# 
#  v3 = gameVer;
#  v4 = 0;
#  v5 = a2;
#  v6 = *(_QWORD *)(qword_18015FAA0 + qword_18002AE20[v3 + 966]);
#  v7 = (__int64 (*)(void))(qword_18015FAA0 + qword_18002AE20[v3 + 897]);
#  v8 = *(_QWORD *)(qword_18015FAA0 + qword_18002AE20[v3 + 1242]);

g_addr_table = 0x18002AE20
game_version_count = 69
g_addr_count = 1242 + game_version_count  # qword_18002AE20 max offset + game_version_count

assert g_addr_count % game_version_count == 0
addr_type_count = int(g_addr_count / game_version_count)

def ReadAddrInfo(ea, addr_count):
    return [get_64bit(ea + i*8) for i in range(0, addr_count) ]

addr_table = ReadAddrInfo(g_addr_table, g_addr_count)

with open('D:/addrtable.h', 'w') as outfile:
    content = '''
#pragma once
#include <stdint.h>

#define addrTypeCount %d
#define addrVerCount %d

uint64_t fullAddrTable[addrTypeCount][addrVerCount] = {
''' % (addr_type_count, game_version_count)
    count = 0
    for h in addr_table:
        if count % game_version_count == 0:
            content += '    { '
        item = "0x%X, " % h
        if count % game_version_count != game_version_count-1:
            content += item
        else:
            content += item[:-2] + ' },\n'
        count += 1
    content += '};\n'
    outfile.write(content)
```