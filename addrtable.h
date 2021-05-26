#pragma once
#include <stdint.h>

#define addrTypeCount 19
#define addrVerCount 69

uint64_t fullAddrTable[addrTypeCount][addrVerCount] = {
    { 0x141402670, 0x1413FFDE4, 0x141406164, 0x141403E98, 0x1414288D0, 0x141426AE8, 0x141433B08, 0x1414318D4, 0x141433B18, 0x1414318D4, 0x14144BEBC, 0x141448D60, 0x141462EA0, 0x14145FA94, 0x14147922C, 0x141477B9C, 0x14147B208, 0x141478DB4, 0x14147A3B4, 0x141478120, 0x141487E98, 0x141485A88, 0x141487EF0, 0x141485A90, 0x141490308, 0x14148DAE0, 0x1414B1A38, 0x1414AEF98, 0x1414CF958, 0x1414CCF18, 0x1414D8AF8, 0x1414D5E80, 0x1414D88F8, 0x1414D6498, 0x1414F2A08, 0x1414EFF90, 0x141504024, 0x141501A64, 0x141525D9C, 0x141522BAC, 0x14152F9D8, 0x14152C95C, 0x14155D744, 0x14155A92C, 0x14155D868, 0x14155A444, 0x141561188, 0x14155D97C, 0x141560E30, 0x14155DB20, 0x1415730DC, 0x14157078C, 0x141573E1C, 0x141571548, 0x1415841D8, 0x141580F6C, 0x1415841D8, 0x141580960, 0x141581CF4, 0x141599F20, 0x141596CB0, 0x141598B4C, 0x141596DB8, 0x1415AFAE8, 0x1415ACA18, 0x1415B0360, 0x1415ADC08, 0x1415C21F4, 0x1415BF65C },
    { 0x142972CC0, 0x14296E540, 0x1429940C0, 0x14298F8C0, 0x142A0D378, 0x142A07D38, 0x142A745D8, 0x142A700A8, 0x142A745D8, 0x142A700A8, 0x142AB3A48, 0x142AAF468, 0x142AD4C48, 0x142ACF648, 0x142AFD1A8, 0x142AF7D48, 0x142AFF4C8, 0x142AFAF48, 0x142B15B88, 0x142B11698, 0x142B64068, 0x142B5FB58, 0x142B64068, 0x142B5FB58, 0x142B81060, 0x142B7C960, 0x142BFB820, 0x142BF62A0, 0x142C02990, 0x142BFE620, 0x142C0F0B0, 0x142C09C30, 0x142C0F0B0, 0x142C09C30, 0x142BD5940, 0x142BD01B0, 0x142BEC240, 0x142BE6DB0, 0x142C5DC38, 0x142C58518, 0x142C6BD28, 0x142C666E8, 0x142C9EB68, 0x142C99598, 0x142C9EB68, 0x142C99598, 0x142D0F2B8, 0x142D09BD8, 0x142D0F2B8, 0x142D09BD8, 0x142D2ED28, 0x142D29778, 0x142D2ED28, 0x142D2A7F8, 0x142D46058, 0x142D40A98, 0x142D46058, 0x142D40A98, 0x142D430B8, 0x142D764A8, 0x142D70C68, 0x142D764A8, 0x142D70C68, 0x142DA0928, 0x142D9C368, 0x142DA98A8, 0x142DA43D8, 0x142D5F528, 0x142D59ED8 },
    { 0x142972CD0, 0x14296E550, 0x1429940D0, 0x14298F8D0, 0x142A0D388, 0x142A07D48, 0x142A745E8, 0x142A700B8, 0x142A745E8, 0x142A700B8, 0x142AB3A58, 0x142AAF478, 0x142AD4C78, 0x142ACF678, 0x142AFD1D8, 0x142AF7D78, 0x142AFF4F8, 0x142AFAF78, 0x142B15BB8, 0x142B116C8, 0x142B64098, 0x142B5FB88, 0x142B64098, 0x142B5FB88, 0x142B81070, 0x142B7C970, 0x142BFB830, 0x142BF62B0, 0x142C029A0, 0x142BFE630, 0x142C0F0C0, 0x142C09C40, 0x142C0F0C0, 0x142C09C40, 0x142BD5950, 0x142BD01C0, 0x142BEC250, 0x142BE6DC0, 0x142C5DC48, 0x142C58528, 0x142C6BD38, 0x142C666F8, 0x142C9EB78, 0x142C995A8, 0x142C9EB78, 0x142C995A8, 0x142D0F2C8, 0x142D09BE8, 0x142D0F2C8, 0x142D09BE8, 0x142D2ED38, 0x142D29788, 0x142D2ED38, 0x142D2A808, 0x142D46068, 0x142D40AA8, 0x142D46068, 0x142D40AA8, 0x142D430C8, 0x142D764B8, 0x142D70C78, 0x142D764B8, 0x142D70C78, 0x142DA0938, 0x142D9C378, 0x142DA98B8, 0x142DA43E8, 0x142D5F538, 0x142D59EE8 },
    { 0x141401DF8, 0x1413FF56C, 0x1414058F8, 0x14140362C, 0x141428064, 0x14142627C, 0x14143329C, 0x141431068, 0x1414332AC, 0x141431068, 0x14144B650, 0x1414484F4, 0x141462634, 0x14145F228, 0x1414789C0, 0x141477330, 0x14147A99C, 0x141478548, 0x141479B48, 0x1414778B4, 0x14148762C, 0x14148521C, 0x141487684, 0x141485224, 0x14148FA9C, 0x14148D274, 0x1414B11CC, 0x1414AE72C, 0x1414CF0EC, 0x1414CC6AC, 0x1414D828C, 0x1414D5614, 0x1414D808C, 0x1414D5C2C, 0x1414F219C, 0x1414EF724, 0x1415037B8, 0x1415011F8, 0x141525564, 0x141522374, 0x14152F1A0, 0x14152C124, 0x14155CD58, 0x141559F40, 0x14155CE7C, 0x141559A58, 0x14156079C, 0x14155CF90, 0x141560444, 0x14155D134, 0x1415726F0, 0x14156FDA0, 0x141573430, 0x141570B5C, 0x1415837EC, 0x141580580, 0x1415837EC, 0x14157FF74, 0x141581308, 0x141599534, 0x1415962C4, 0x141598160, 0x1415963CC, 0x1415AF0FC, 0x1415AC02C, 0x1415AF974, 0x1415AD21C, 0x1415C1808, 0x1415BEC70 },
    { 0x142A6EAAC, 0x142A6A32C, 0x142A8FF1C, 0x142A8B714, 0x142B0933C, 0x142B03CEC, 0x142B7059C, 0x142B6C06C, 0x142B7059C, 0x142B6C06C, 0x142BAFA6C, 0x142BAB48C, 0x142BD1F1C, 0x142BCC91C, 0x142BFA7FC, 0x142BF539C, 0x142BFCB1C, 0x142BF859C, 0x142C131CC, 0x142C0ECDC, 0x142C616AC, 0x142C5D19C, 0x142C616AC, 0x142C5D19C, 0x142C7E67C, 0x142C79F7C, 0x142CF8E4C, 0x142CF38CC, 0x142CFE8AC, 0x142CFA53C, 0x142D0AFDC, 0x142D05B5C, 0x142D0AFDC, 0x142D05B5C, 0x142CD186C, 0x142CCC0DC, 0x142CE816C, 0x142CE2CDC, 0x142D59B4C, 0x142D5441C, 0x142D67CCC, 0x142D6267C, 0x142D9AAFC, 0x142D9552C, 0x142D9AAFC, 0x142D9552C, 0x142E0B24C, 0x142E05B6C, 0x142E0B24C, 0x142E05B6C, 0x142E2ACDC, 0x142E2572C, 0x142E2ACDC, 0x142E267AC, 0x142E4211C, 0x142E3CB5C, 0x142E4211C, 0x142E3CB5C, 0x142E3F17C, 0x142E7255C, 0x142E6CD1C, 0x142E7255C, 0x142E6CD1C, 0x142E9C9DC, 0x142E9841C, 0x142EA595C, 0x142EA048C, 0x142E5B5CC, 0x142E55F7C },
    { 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830, 0x830 },
    { 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838, 0x838 },
    { 0x1425F9618, 0x1425F5FA8, 0x14260F918, 0x14260C228, 0x14262C090, 0x142627B10, 0x1426A0310, 0x14269CE90, 0x1426A0310, 0x14269CE90, 0x1426ABDA0, 0x1426A88A0, 0x1426CB920, 0x1426C7420, 0x1426E9620, 0x1426E5290, 0x1426EB920, 0x1426E8490, 0x142704FA0, 0x142701BA0, 0x142736FA0, 0x142733B90, 0x142736FA0, 0x142733B90, 0x142743B20, 0x142740510, 0x1427BE290, 0x1427B9E10, 0x1427E32A0, 0x1427E0010, 0x1427EF890, 0x1427EB520, 0x1427EF890, 0x1427EB520, 0x142813920, 0x14280F2A0, 0x14282A210, 0x142825EA0, 0x14289BB20, 0x142897518, 0x1428A9C30, 0x1428A56A8, 0x1428DCA30, 0x1428D8530, 0x1428DCA30, 0x1428D8530, 0x14294D6B0, 0x1429490B0, 0x14294D6B0, 0x1429490B0, 0x142969120, 0x142964C20, 0x142969120, 0x142965CA0, 0x1429800A0, 0x14297BBA0, 0x1429800A0, 0x14297BBA0, 0x14297DF28, 0x14299EB38, 0x14299A3B8, 0x14299EB38, 0x14299A3B8, 0x1429BCFB8, 0x1429B9AB8, 0x1429C5F38, 0x1429C1A50, 0x1429DA150, 0x1429D5BD0 },
    { 0x142972DF0, 0x14296E670, 0x1429941F0, 0x14298F9F0, 0x142A0D4B0, 0x142A07E70, 0x142A74710, 0x142A701E0, 0x142A74710, 0x142A701E0, 0x142AB3B80, 0x142AAF5A0, 0x142AD4DC0, 0x142ACF7C0, 0x142AFD320, 0x142AF7EC0, 0x142AFF640, 0x142AFB0C0, 0x142B15D00, 0x142B11810, 0x142B641E0, 0x142B5FCD0, 0x142B641E0, 0x142B5FCD0, 0x142B811A0, 0x142B7CAA0, 0x142BFB960, 0x142BF63E0, 0x142C02AD0, 0x142BFE760, 0x142C0F1F0, 0x142C09D70, 0x142C0F1F0, 0x142C09D70, 0x142BD5A80, 0x142BD02F0, 0x142BEC380, 0x142BE6EF0, 0x142C5DD70, 0x142C58650, 0x142C6BE60, 0x142C66820, 0x142C9ECA0, 0x142C996D0, 0x142C9ECA0, 0x142C996D0, 0x142D0F3F0, 0x142D09D10, 0x142D0F3F0, 0x142D09D10, 0x142D2EE60, 0x142D298B0, 0x142D2EE60, 0x142D2A930, 0x142D46190, 0x142D40BD0, 0x142D46190, 0x142D40BD0, 0x142D431F0, 0x142D765E0, 0x142D70DA0, 0x142D765E0, 0x142D70DA0, 0x142DA0A60, 0x142D9C4A0, 0x142DA99E0, 0x142DA4510, 0x142D5F660, 0x142D5A010 },
    { 0x1427B9250, 0x1427B5B90, 0x1427CF550, 0x1427CBE10, 0x1427EBBB8, 0x1427E7750, 0x14285FF40, 0x14285CAC8, 0x14285FF40, 0x14285CAC8, 0x14286B5C0, 0x1428680C0, 0x14288B158, 0x142887048, 0x1428A9288, 0x1428A4EE0, 0x1428AB588, 0x1428A80E0, 0x1428C4C08, 0x1428C17E0, 0x1428F6C08, 0x1428F37E0, 0x1428F6C08, 0x1428F37E0, 0x1429037D0, 0x1429001A0, 0x14297DF58, 0x142979AA0, 0x1429A2F58, 0x14296E380, 0x1429AF558, 0x142979880, 0x1429AF558, 0x142979880, 0x1429D35D8, 0x14299D600, 0x1429E9ED8, 0x1429B4200, 0x142A5B7E0, 0x142A25880, 0x142A698E0, 0x142A33A40, 0x142A9C6D8, 0x142A668C8, 0x142A9C6D8, 0x142A668C8, 0x142B0D358, 0x142AD7448, 0x142B0D358, 0x142AD7448, 0x142B2CDD8, 0x142AF6FC0, 0x142B2CDD8, 0x142AF8040, 0x142B43D58, 0x142B0DF40, 0x142B43D58, 0x142B0DF40, 0x142B10540, 0x142B62A60, 0x142B2C9C0, 0x142B62A60, 0x142B2C9C0, 0x142B8CEE0, 0x142B580C0, 0x142B95E60, 0x142B60140, 0x142B78840, 0x142B74310 },
    { 0x141EDFEBC, 0x141EDF9C8, 0x141ED937C, 0x141ED88B8, 0x141EF25E0, 0x141EECECC, 0x141F65AD0, 0x141F70C28, 0x141F65AD0, 0x141F70C28, 0x141F7DBBC, 0x141F6C8E0, 0x141F98938, 0x141F87494, 0x141FA92C4, 0x141FA3B00, 0x141FB80FC, 0x141FA62F0, 0x141FB5454, 0x141FA3684, 0x141FE7DE4, 0x141FD6130, 0x141FE7DE4, 0x141FD6130, 0x141FE5AA4, 0x141FE3010, 0x14205DABC, 0x142058794, 0x14207F980, 0x14208B5C0, 0x142098670, 0x142096AAC, 0x142098670, 0x142096AAC, 0x1420AB990, 0x1420A5390, 0x1420CE26C, 0x1420BD19C, 0x14212946C, 0x1421334BC, 0x1421372E4, 0x142134158, 0x142172EF0, 0x142171300, 0x142172EF0, 0x142171300, 0x1421D7248, 0x1421E01D4, 0x1421D7248, 0x1421E01D4, 0x1421EFBD8, 0x1421F97DC, 0x1421EFBD8, 0x1421FA85C, 0x1422049CC, 0x14220D4B4, 0x1422049CC, 0x14220D4B4, 0x142202B7C, 0x14221F9DC, 0x142229B00, 0x14221F9DC, 0x142229B00, 0x14223F6C8, 0x142248BE8, 0x142247768, 0x14224FB8C, 0x14225898C, 0x142257564 },
    { 0x141EDFEC4, 0x141EDF9CC, 0x141ED93CC, 0x141ED8908, 0x141EF25E4, 0x141EECF18, 0x141F65AD4, 0x141F70C2C, 0x141F65AD4, 0x141F70C2C, 0x141F7DBC0, 0x141F6C8E8, 0x141F98944, 0x141F874A0, 0x141FA92E4, 0x141FA3B20, 0x141FB8108, 0x141FA62F4, 0x141FB545C, 0x141FA368C, 0x141FE7DE8, 0x141FD6138, 0x141FE7DE8, 0x141FD6138, 0x141FE5AA8, 0x141FE3014, 0x14205DAC8, 0x1420587A0, 0x14207F98C, 0x14208B5C8, 0x142098678, 0x142096ABC, 0x142098678, 0x142096ABC, 0x1420AB994, 0x1420A5398, 0x1420BE7A0, 0x1420BD1A4, 0x142129470, 0x1421334C0, 0x1421372E8, 0x14213415C, 0x142172EF4, 0x142171304, 0x142172EF4, 0x142171304, 0x1421D724C, 0x1421E01D8, 0x1421D724C, 0x1421E01D8, 0x1421EFBDC, 0x1421F97E0, 0x1421EFBDC, 0x1421FA860, 0x1422049FC, 0x14220D4EC, 0x1422049FC, 0x14220D4EC, 0x142203274, 0x14221F9E0, 0x142229B04, 0x14221F9E0, 0x142229B04, 0x14223F6D4, 0x142248BF0, 0x142247778, 0x14224FBA0, 0x142258994, 0x142257568 },
    { 0x141408914, 0x141405FCC, 0x14140C524, 0x141536604, 0x14142EB70, 0x14142CCB0, 0x141439CC0, 0x141437A00, 0x141439CD0, 0x141437A00, 0x1414520D0, 0x14144EEC0, 0x141468FF4, 0x141465C88, 0x14147F4FC, 0x14147DDE0, 0x1414813E0, 0x14147F000, 0x14148061C, 0x14147E2A0, 0x14148DFF8, 0x14148BCF4, 0x14148E03C, 0x14148BCFC, 0x14149663C, 0x141493C9C, 0x1414B7D14, 0x1414B518C, 0x1414D5ABC, 0x1414D313C, 0x1414DED9C, 0x1414DC0DC, 0x1414DEB58, 0x1414DC740, 0x1414F8C4C, 0x1414F61CC, 0x14150A234, 0x141507DA0, 0x14152BFB4, 0x141528E10, 0x1415359E4, 0x141532994, 0x1415638C4, 0x141560948, 0x141563990, 0x14156040C, 0x1415671C0, 0x14156394C, 0x141566ED4, 0x141563CB8, 0x14157909C, 0x14157682C, 0x141579DC0, 0x1415774E8, 0x14158A1AC, 0x14158701C, 0x14158A1AC, 0x141586904, 0x141587D4C, 0x14159FF70, 0x14159CD40, 0x14159EC28, 0x14159CE48, 0x1415B5B78, 0x1415B2B24, 0x1415B63D0, 0x1415B3D38, 0x1415C8264, 0x1415C5630 },
    { 0x141406DC4, 0x14140447C, 0x14140A9D4, 0x141534AB4, 0x14142D01C, 0x14142B160, 0x141438170, 0x141435EB0, 0x141438180, 0x141435EB0, 0x14145054C, 0x14144D33C, 0x141467470, 0x141464100, 0x14147D968, 0x14147C248, 0x14147F84C, 0x14147D46C, 0x14147EA88, 0x14147C70C, 0x14148C464, 0x14148A160, 0x14148C4A8, 0x14148A168, 0x141494AA4, 0x141492108, 0x1414B6180, 0x1414B35F8, 0x1414D3F28, 0x1414D15A8, 0x1414DD1FC, 0x1414DA548, 0x1414DCFC4, 0x1414DABAC, 0x1414F70B8, 0x1414F4638, 0x141508694, 0x14150620C, 0x14152A420, 0x14152727C, 0x141533EC8, 0x141530E78, 0x141561DA8, 0x14155EE2C, 0x141561E74, 0x14155E8F0, 0x1415656A4, 0x141561E30, 0x1415653B8, 0x14156219C, 0x141577580, 0x141574D10, 0x1415782A4, 0x1415759CC, 0x141588684, 0x141585500, 0x141588690, 0x141584DE8, 0x141586230, 0x14159E454, 0x14159B224, 0x14159D0CC, 0x14159B32C, 0x1415B405C, 0x1415B1008, 0x1415B48B4, 0x1415B221C, 0x1415C6748, 0x1415C3B14 },
    { 0x142973788, 0x14296F008, 0x142994C00, 0x1429A1920, 0x142A0DE50, 0x142A08808, 0x142A750A8, 0x142A70B78, 0x142A750A8, 0x142A70B78, 0x142AB4518, 0x142AAFF38, 0x142AD57D0, 0x142AD01D0, 0x142AFDB28, 0x142AF86C8, 0x142AFFE48, 0x142AFB8C8, 0x142B164A8, 0x142B11FA8, 0x142B64978, 0x142B60468, 0x142B64978, 0x142B60468, 0x142B81978, 0x142B7D278, 0x142BFC118, 0x142BF6B98, 0x142C03288, 0x142BFEF18, 0x142C0F9A8, 0x142C0A520, 0x142C0F9A8, 0x142C0A520, 0x142BD6230, 0x142BD0AA0, 0x142BECB30, 0x142BE76A0, 0x142C5E790, 0x142C59070, 0x142C6C880, 0x142C67240, 0x142C9F6C0, 0x142C9A0F8, 0x142C9F6C0, 0x142C9A0F8, 0x142D0FE10, 0x142D0A738, 0x142D0FE10, 0x142D0A738, 0x142D2F888, 0x142D2A2D8, 0x142D2F888, 0x142D2B358, 0x142D46B40, 0x142D41580, 0x142D46B40, 0x142D41580, 0x142D43BA0, 0x142D76F90, 0x142D71750, 0x142D76F90, 0x142D71750, 0x142DA1410, 0x142D9CE50, 0x142DAA390, 0x142DA4EC0, 0x142D60010, 0x142D5A9C0 },
    { 0x1424B0FF0, 0x1424AB4B8, 0x1424BB050, 0x1424B1398, 0x1424D5248, 0x1424D0408, 0x142545DA0, 0x142542018, 0x142545DA0, 0x142542018, 0x142554470, 0x14254B498, 0x142573BF0, 0x14256A5F8, 0x142588F78, 0x142589938, 0x14258B290, 0x14258CCC8, 0x1425A9920, 0x1425A81D0, 0x1425DF1C0, 0x1425D7B18, 0x1425DF1C0, 0x1425D7B18, 0x1425E78C8, 0x1425E6088, 0x1426595D8, 0x14265C340, 0x14267D720, 0x14267D088, 0x142687C58, 0x1426866D8, 0x142687C58, 0x1426863B8, 0x1426AF920, 0x1426B0F18, 0x1426CCA70, 0x1426C13A8, 0x14273B210, 0x1427310C8, 0x142748E68, 0x142743E30, 0x142775960, 0x142778FF8, 0x142775960, 0x142778FF8, 0x1427EC1B8, 0x1427E6160, 0x1427EC1B8, 0x1427E6160, 0x142804F60, 0x1427FA770, 0x142804F60, 0x1427FB7F0, 0x142819AF0, 0x142818728, 0x142819AF0, 0x142818728, 0x142819E90, 0x142833EE0, 0x142830658, 0x142833EE0, 0x142830658, 0x14284B8C0, 0x14284C868, 0x1428547F8, 0x142856E88, 0x142869DC0, 0x142869D98 },
    { 0x14217F370, 0x14217C2A0, 0x142184690, 0x142181578, 0x14219C220, 0x142197CC0, 0x142210458, 0x14220CE10, 0x142210458, 0x14220CE10, 0x14221AA88, 0x142217D88, 0x142235D40, 0x1422317F8, 0x142251F48, 0x14224E388, 0x142254280, 0x142250D80, 0x142252650, 0x14224F1D8, 0x1422845A0, 0x1422810D8, 0x1422845A0, 0x1422810D8, 0x14228FDE8, 0x14228CC98, 0x1423079C0, 0x142303288, 0x14232BE50, 0x142329118, 0x142337BB0, 0x142333C88, 0x142337BB0, 0x142333C88, 0x142355AC0, 0x142351308, 0x14236AC00, 0x142366CF0, 0x1423D62B0, 0x1423D1BC0, 0x1423E2138, 0x1423DE128, 0x142413080, 0x14240F200, 0x142413080, 0x14240F200, 0x142483C50, 0x14247FAC0, 0x142483C50, 0x14247FAC0, 0x14249BD18, 0x142497E88, 0x14249BD18, 0x142498F08, 0x1424B0AA0, 0x1424AC9B8, 0x1424B0AA0, 0x1424AC9B8, 0x1424AEB30, 0x1424CCF08, 0x1424C8768, 0x1424CCF08, 0x1424C8768, 0x1424EA050, 0x1424E6F88, 0x1424F3020, 0x1424EEFF0, 0x1425060A0, 0x142502300 },
    { 0x1421A32D8, 0x1421A31B0, 0x1421A8708, 0x1421A83D8, 0x1421BFD38, 0x1421BD308, 0x142236CD8, 0x142232728, 0x142236CD8, 0x142232728, 0x142241C30, 0x14223EA58, 0x142259B40, 0x142254AE8, 0x142279328, 0x1422724E0, 0x142277740, 0x142275670, 0x142275B40, 0x142273D10, 0x1422A7B60, 0x1422A84E0, 0x1422A7B60, 0x1422A84E0, 0x1422B3218, 0x1422B1980, 0x14232ACC0, 0x142327B18, 0x142351530, 0x14234F5C0, 0x14235DA70, 0x14235A9C0, 0x14235DA70, 0x14235A9C0, 0x142378C80, 0x1423785E8, 0x142391458, 0x14238D380, 0x1423FAAF8, 0x1423F5458, 0x142409848, 0x1424027D8, 0x142439418, 0x1424348E0, 0x142439418, 0x1424348E0, 0x1424A9870, 0x1424A3718, 0x1424A9870, 0x1424A3718, 0x1424BFD70, 0x1424BB9B8, 0x1424BFD70, 0x1424BCA38, 0x1424D7540, 0x1424D4310, 0x1424D7540, 0x1424D4310, 0x1424D5588, 0x1424F15C8, 0x1424ECFA0, 0x1424F15C8, 0x1424ECFA0, 0x142511BC0, 0x14250D798, 0x14251AD40, 0x142515840, 0x14252CBB0, 0x142525DA8 },
    { 0x14218EB60, 0x14218B800, 0x142193D88, 0x142190AA0, 0x1421AB780, 0x1421A72E0, 0x14221F8A8, 0x14221C560, 0x14221F8A8, 0x14221C560, 0x14222A248, 0x142226F28, 0x142244E98, 0x142240CD8, 0x1422616F0, 0x14225D558, 0x142263810, 0x1422606D8, 0x142261BE0, 0x14225EBF0, 0x142293970, 0x142290890, 0x142293970, 0x142290890, 0x14229F2A0, 0x14229BFD0, 0x142316F08, 0x142312AC0, 0x14233B3A8, 0x142338538, 0x1423470B8, 0x1423430D8, 0x1423470B8, 0x1423430D8, 0x142364E40, 0x142360890, 0x14237A488, 0x142376340, 0x1423E5720, 0x1423E1468, 0x1423F1930, 0x1423ED890, 0x1424230A8, 0x14241EF70, 0x1424230A8, 0x14241EF70, 0x142493B20, 0x14248F838, 0x142493B20, 0x14248F838, 0x1424ABCE8, 0x1424A7910, 0x1424ABCE8, 0x1424A8990, 0x1424C0948, 0x1424BC830, 0x1424C0948, 0x1424BC830, 0x1424BEA50, 0x1424DCE00, 0x1424D8740, 0x1424DCE00, 0x1424D8740, 0x1424F9EA8, 0x1424F6CC8, 0x142502E38, 0x1424FED28, 0x142516090, 0x142511F20 },
};