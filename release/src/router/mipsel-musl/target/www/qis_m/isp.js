var city = [["Arhangelsk", "Архангельск"], ["Astrakhan", "Астрахань"], ["Balakovo", "Балаково"], ["Barnaul", "Барнаул"],
["Bataisk", "Батайск"], ["Berdsk", "Бердск"], ["Bryansk", "Брянск"], ["Vladisvostok", "Владивосток"],
["Volgograd", "Волгоград"], ["Volzhsky", "Волжский"], ["Voronezh", "Воронеж"], ["Vsevolozhsk", "Всеволжск"],
["Desnogorsk", "Десногорск"], ["Dzerzhinsk", "Дзержинск"], ["Dimitrovgrad", "Димитровград"], ["Domodedovo", "Домодедово"],
["Ekaterinburg", "Екатеринбург"], ["Zheleznogorsk", "Железногорск"], ["Zelenograd", "Зеленоград"], ["Ivanovo", "Иваново"],
["Izhevsk", "Ижевск"], ["Irkutsk", "Иркутск"], ["Irkutsk/Region", "Иркутск/область"], ["Ioshkar-Ola", "Йошкар-Ола"],
["Kazan", "Казань"], ["Kaliningrad", "Калининград"], ["Kaluga", "Калуга"], ["Kashira", "Кашира"], ["Kemerovo", "Кемерово"],
["Kirov", "Киров"], ["Kolpino", "Кемерово"], ["Korolev", "Королев"], ["Kokhma", "Кохма"], ["Krasnogorsk", "Красногорск"], ["Krasnodar", "Краснодар"],
["Krasnoobsk", "Краснообск"], ["Krasnoyarsk", "Красноярск"], ["Krasnoyarsk/Region", "Красноярск/область"], ["Kursk", "Курск"],
["Lipetsk", "Липецк"], ["Lyubertsy", "Люберцы"], ["Moscow", "Москва"], ["MoskowRegion", "Московскаяобласть"],
["NaberezhnieChelni", "НабережныеЧелны"], ["Neftekamsk", "Нефтекамск"], ["Nizhnekamsk", "Нижнекамск"], //43
["NizhniyNovgorod", "НижнийНовгород"], ["Novomoskovsk", "Новомосковск"], ["Novosibirsk/Region", "Новосибирск/область"], //46
["Noginsk", "Ногинск"], ["Oktyabrsky", "Октябрьский"], ["Omsk/Region", "Омск/область"], ["Orel", "Орёл"], //49
["Orenburg", "Оренбург"], ["PavlovskyPosad", "ПавловскийПосад"], ["Penza", "Пенза"], ["Perm", "Пермь"], //53
["Rostov-na-Donu", "Ростов-на-Дону"], ["Ryazan", "Рязань"], ["Samara", "Самара"], ["Sankt-Peterburg", "Санкт-Петербург"], //57
["Saratov", "Саратов"], ["Severodvinsk", "Северодвинск"], ["Smolensk", "Смоленск"], ["Sochi", "Сочи"], ["Tver", "Тверь"], //61
["Togliatti", "Тольятти"], ["Tula", "Тула"], ["Tutaev", "Тутаев"], ["Tumen", "Тюмень"], ["Uzlovaya", "Краснодар"], //66
["Ulyanovsk", "Ульяновск"], ["Ufa", "Уфа"], ["Khabarovsk", "Хабаровск"], ["Cheboksari", "Чебоксары"], //71
["Chelabinsk", "Челябинск"], ["Cherepovez", "Череповец"], ["Shatura", "Шатура"], ["Schekino", "Щёкино"],//75
["Elektrostal", "Электросталь"], ["Engels", "Энгельс"], ["Yaroslavl", "Ярославль"]//79
];
var isp = ["Beeline", "ACT", "Delta-Telecom", "Telecom-Service", "Intelbi", "Intelica", "HomeNET", "DOM.RU", //0
"Tower-Telecom(STARNET)", "Centralink", "Golden Telecom", "Intercon", "Kabinet", "Olympus", "Planeta", //8
"Ural Telephone Company", "UTK", "Delovaya Set", "IRKNET TELECOM", "Corbina", "Infoline", "Vermont-IT", //15
"Elcom-Telecom", "Stream", "KrasLan", "OrionTelecom", "RightSide", "SiberiaNet", "2KOM", "Butovo.com", //22
"CPMS", "CROSSNET", "Degunino.net", "Dubki.Ru", "EAST Telecom", "Hovrino.ru", "IMSYS", "InfiniteNet", //30
"Interlan(Nord-East)", "Interlan(SouthandSouth-West)", "Izumrud-Service", "Konkovo.net", "Korvet-Telecom", //38
"Kurkino.net", "LIFELINK", "Localka", "Masterlink", "Metronet", "MOSINTER", "Net-by-Net", "Onlime", //43
"OSTnet.ru", "Procenter.ru", "Promira.net", "Prov.ru", "QWERTY", "Rusteko", "SigmaCom", "Starlink-Telecom", //51
"Starnet", "Sviblovo OnLine", "Tartila.net", "Tushino.ru", "Tushino-Telecom", "Ultranet.ru", //59
"Utech(UniversalTechnology)", "Yasenevo Online", "Yauza Telecom", "Flex", "HimkiNET", "Infolink", //65
"Agentstvo Delovoy Svazi", "Academ.org", "CITY", "ComGate", "HomeNet(Auto)", "HomeNet(Static)", //71
"NIR-Telecom", "NovoTelecom", "Siberian Nets", "TTK-3C", "ElectroCom", "Interlink", "InterTelecom", //77
"Multinex", "N-Link", "RyazanTelecom", "UroksTelecom", "Kraft-S", "MetroMax", "Samsra-Internet", //84
"Tahion", "TTK", "VolgaOnLine", "Cubio", "Demos Datcom", "Eltel", "Interzet", "Matrix", "Nienshants", //91
"Ozerki.Net", "SatNet", "Sky Net", "Togliatti-Telecom", "Altair", "Enforta", "Garant", "ITService", //100
"Sun-Link", "Dars IP", "Strim", "Ultramarine", "NetTrans", "Ufanet(Auto)", "Ufanet(Static)", //108
"Internet-Center(Chebnet)", "Insit", "Intersviaz", "Trigor", "U-net(auto)", "U-net(static)", "LANK Telecom",//115
"RTS Ribinsk" //122
];
var wantype = ["PPTP", "PPPOE", "Static IP", "DHCP", "L2TP", "PPTP(192.168.0.1)", "PPTP(192.168.1.1)", "PPTP(192.168.0.60)", //0
"PPTP(192.168.0.64)", "L2TP+IPTV", "DHCP(Tarificate)", "PPTP(Unlim PPTP)", "PPTP(Unlim public IP - central)", //8
"PPTP(Unlim public IP - ppp)", "PPTP (vpn2)", "PPTP (unlim3)", "PPTP (real)", "PPTP (80.252.128.110)", //13
"PPTP (10.255.255.32)", "PPTP (vpn-gw1)", "PPTP (vpn-gw2)", "PPTP (vpn-gw3)", "PPTP (vpn)", "PPTP (unlim)" //18
];
var service = [ [0, 0, 0, 96], //Arhangelsk
[1, 1, 1, 112], [1, 0, 0, 96], [1, 2, 1, 96], [1, 3, 0, 255], //Astrakhan
[2, 0, 0, 96], //Balakovo
[3, 4, 2, 15], [3, 5, 2, 15], //Barnaul
[4, 0, 0, 96], //Bataisk
[5, 6, 3, 16], //Berdsk
[6, 0, 0, 96], //Bryansk
[7, 0, 0, 96], //Vladisvostok
[8, 0, 0, 96], [8, 7, 1, 112], //Volgograd
[9, 0, 0, 96], [9, 7, 1, 112], [9, 8, 0, 112], //Volzhsky
[10, 0, 0, 96], [10, 9, 0, 239], [10, 10, 0, 112], [10, 11, 1, 112], //Voronezh
[11, 0, 0, 96], //Vsevolozhsk
[12, 0, 0, 96], //Desnogorsk
[13, 0, 0, 96], //Dzerzhinsk
[14, 0, 0, 96], //Dimitrovgrad
[15, 0, 0, 96], //Domodedovo
[16, 0, 0, 96], [16, 12, 0, 255], [16, 13, 0, 127], [16, 14, 3, 16], [16, 15, 0, 119], [16, 16, 0, 127], //Ekaterinburg
[17, 0, 0, 96], //Zheleznogorsk
[18, 0, 0, 96], //Zelenograd
[19, 0, 0, 96], //Ivanovo
[20, 7, 1, 112], //Izhevsk
[21, 0, 0, 96], //Irkutsk
[22, 17, 1, 96], [22, 18, 1, 112], //Irkutsk/Region
[23, 7, 1, 112], //Ioshkar-Ola
[24, 7, 1, 112], //Kazan
[25, 0, 0, 96], //Kaliningrad
[26, 0, 0, 96], [26, 19, 4, 96], //Kaluga
[27, 0, 0, 96], //Kashira
[28, 0, 0, 96], //Kemerovo
[29, 7, 1, 112], //Kirov
[30, 0, 0, 96], //Kolpino
[31, 20, 1, 112], [31, 21, 2, 31], //Korolev
[32, 0, 0, 96], //Kokhma
[33, 22, 5, 119], [33, 22, 6, 119], [33, 22, 7, 119], [33, 22, 8, 119], //Krasnogorsk
[34, 0, 0, 96], [34, 23, 0, 96], //Krasnodar
[35, 6, 3, 16], //Krasnoobsk
[36, 0, 0, 96], [36, 24, 1, 112], [36, 25, 1, 112], [36, 26, 0, 240], //Krasnoyarsk
[37, 27, 1, 112], //Krasnoyarsk/Region
[38, 0, 0, 96], //Kursk
[39, 0, 0, 96], [39, 19, 4, 96], //Lipetsk
[40, 0, 0, 96], //Lyubertsy
[41, 28, 0, 247], [41, 0, 0, 96], [41, 29, 0, 112], [41, 19, 9, 96], [41, 30, 3, 16],
[41, 31, 2, 31], [41, 32, 0, 127], [41, 33, 3, 16], [41, 34, 0, 119], [41, 10, 0, 112],
[41, 35, 10, 16], [41, 35, 11, 112], [41, 35, 12, 112], [41, 35, 13, 112], [41, 36, 3, 16],
[41, 37, 0, 112], [41, 38, 0, 112], [41, 39, 0, 112], [41, 40, 0, 119], [41, 41, 1, 112],
[41, 42, 2, 31], [41, 43, 3, 16], [41, 44, 1, 112], [41, 44, 0, 112], [41, 45, 3, 16],
[41, 45, 0, 127], [41, 46, 1, 112], [41, 46, 0, 112], [41, 47, 3, 16], [41, 48, 2, 23],
[41, 49, 0, 112], [41, 49, 1, 112], [41, 50, 3, 16], [41, 51, 2, 23], [41, 52, 2, 23],
[41, 53, 0, 112], [41, 54, 2, 23], [41, 55, 2, 23], [41, 55, 3, 16], [41, 56, 2, 31],
[41, 56, 0, 112], [41, 57, 14, 112], [41, 57, 15, 112], [41, 57, 16, 112], [41, 58, 3, 16],
[41, 58, 1, 112], [41, 58, 0, 112], [41, 59, 1, 127], [41, 60, 0, 112], [41, 61, 0, 112],
[41, 62, 10, 16], [41, 62, 11, 112], [41, 62, 12, 112], [41, 62, 13, 112], [41, 63, 1, 119],
[41, 64, 10, 16], [41, 64, 11, 112], [41, 64, 12, 112], [41, 64, 13, 112], [41, 65, 1, 112],
[41, 66, 2, 23], [41, 67, 2, 31],
[42, 34, 0, 119], [42, 68, 17, 127], [42, 68, 18, 127], [42, 69, 0, 119], [42, 20, 1, 112],
[42, 70, 2, 23],//MoskowRegion
[43, 7, 1, 112], //NaberezhnieChelni
[44, 0, 0, 96], //Neftekamsk
[45, 7, 1, 112], //Nizhnekamsk
[46, 71, 0, 96], [46, 0, 0, 96], [46, 7, 1, 112], //NizhniyNovgorod
[47, 0, 0, 96], //Novomoskovsk
[48, 72, 3, 16], [48, 73, 2, 31], [48, 74, 3, 16], [48, 7, 1, 112], [48, 75, 3, 16],
[48, 76, 2, 31], [48, 77, 3, 16], [48, 78, 3, 16], [48, 79, 3, 16], [48, 79, 0, 112],
[48, 80, 3, 16], //Novosibirsk/Region
[49, 0, 0, 96], //Noginsk
[50, 0, 0, 96], //Oktyabrsky
[51, 7, 1, 112], //Omsk/Region
[52, 0, 0, 96], //Orel
[53, 0, 0, 96], [53, 19, 4, 96], [53, 7, 1, 112], //Orenburg
[54, 0, 0, 96], //PavlovskyPosad
[55, 7, 1, 112], //Penza
[56, 0, 0, 96], [56, 7, 1, 112], //Perm
[57, 0, 0, 96], [57, 19, 4, 96], //Rostov-na-Donu
[58, 81, 3, 16], [58, 82, 1, 112], [58, 83, 1, 112], [58, 84, 0, 96], [58, 85, 0, 111],
[58, 86, 2, 31], [58, 87, 3, 16], //Ryazan
[59, 0, 0, 96], [59, 7, 1, 112], [59, 10, 0, 96], [59, 88, 2, 31], [59, 89, 1, 112],
[59, 90, 2, 31], [59, 91, 2, 31], [59, 92, 1, 119], [59, 93, 1, 112], //Samara
[60, 0, 0, 96], [60, 19, 4, 96], [60, 94, 1, 112], [60, 95, 1, 112], [60, 96, 1, 112],
[60, 97, 2, 31], [60, 98, 19, 119], [60, 98, 20, 119], [60, 98, 21, 119], [60, 98, 2, 23],
[60, 99, 2, 31], [60, 100, 0, 127], [60, 101, 1, 112], [60, 102, 1, 112], //Sankt-Peterburg
[61, 0, 0, 96], [61, 19, 4, 96], //Saratov
[62, 0, 0, 96], //Severodvinsk
[63, 0, 0, 96], //Smolensk
[64, 0, 0, 96], //Sochi
[65, 0, 0, 96], //Tver
[66, 0, 0, 96], [66, 10, 0, 112], [66, 103, 0, 96], //Togliatti
[67, 104, 1, 96], [67, 0, 0, 96], [67, 19, 4, 96], [67, 105, 1, 96], [67, 106, 1, 96],
[67, 107, 2, 31], [67, 108, 1, 96], //Tula
[68, 0, 0, 96],//Tutaev
[69, 7, 1, 112],//Tumen
[70, 0, 0, 96],//Uzlovaya
[71, 0, 0, 96], [71, 19, 4, 96], [71, 109, 2, 31], [71, 110, 2, 31], [71, 111, 0, 224],//Ulyanovsk
[72, 0, 0, 96], [72, 112, 0, 112], [72, 113, 0, 112], [72, 114, 0, 127],//Ufa
[73, 0, 0, 96], //Khabarovsk
[74, 115, 0, 112],//Cheboksari
[75, 7, 1, 112], [75, 116, 0, 96], [75, 117, 1, 96], [75, 117, 0, 96], [75, 118, 22, 112],
[75, 118, 23, 112], [75, 119, 0, 224], [75, 120, 0, 239],//Chelabinsk
[76, 0, 0, 96],//Cherepovez
[77, 0, 0, 96],//Shatura
[78, 0, 0, 96],//Schekino
[79, 0, 0, 96],//Elektrostal
[80, 0, 0, 96],//Engels
[81, 0, 0, 96], [81, 19, 4, 96], [81, 121, 0, 112], [81, 121, 1, 96], [81, 122, 2, 31]//Yaroslavl
];

