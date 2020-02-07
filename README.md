# GTAHashMap
GTAHashMap dumped from Alexander Blade's ScriptHookV.dll

# Reversing
```
IDA: nativeInit(int64 a1):
    arg a1 is oldHash
    switch(gameVersion_dw)
    0x1884 is hashinfo count
    jump table is hashtable
```

```c
struct hashinfo {
    uint64_t   oldHash;
    uint64_t   hash[21];
};

struct hashtable {
    hashinfo[0x1884];
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
    54,55           21      // 1.0.1868.0 STEAM == 54
}
```

Optimized
```c
static int searchDepth = 21; /* 0 to 21 */
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

g_hashtable = 0x18002BDD0
g_hashinfo_count = 0x1884
g_hash_count = 22

def ReadHashInfo(ea, hash_count):
    return [get_64bit(ea + i*8) for i in range(0, hash_count) ]

def ReadHashTable(ea, hashinfo_count, hash_count):
    return [ReadHashInfo(ea + i*8*hash_count, hash_count) for i in range(0, hashinfo_count)]

hashtable = ReadHashTable(g_hashtable, g_hashinfo_count, g_hash_count)

with open('D:/hashmap.h', 'w') as outfile:
    content = '''
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
