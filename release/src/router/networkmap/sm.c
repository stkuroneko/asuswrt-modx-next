#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sm.h>
#include <json.h>

struct _convType convTypes[] = {
/*
        Unknown         0
        Windows device  1
        Router          2
        Router          3
        NAS/Server      4
        IP Cam          5
        Macbook         6
        Game Console    7
        Game Console    8
        Android Phone   9
        iPhone          10
        Apple TV        11
        Set-top Box     12
        Windows device  13
        iMac            14
        ROG             15
        Game Console    16
        Game Console    17
        Printer         18
        Windows Phone   19
        Android Tablet  20
        iPad            21
        Linux Device    22
        Smart TV        23
        Repeater        24
        Kindle          25
        Scanner         26
        Chromecast      27
        ASUS smartphone 28
        ASUS Pad        29
        Windows         30
        Android         31
        Mac OS          32
#       Smartphone      33
        Desktop         34
        Windows laptop  35
        ROG Client      36 refer rog_clientlist
*/
	{ 1,    "win",		2},
        { 1,    "pc",		2},
        { 1,    "nb",		2},
        { 2,    "rt-",		0},
        { 2,    "dsl-",		0},
        { 2,    "pl-",		0},
        { 4,    "storage",	0},
        { 4,    "nas",		0},
        { 5,    "cam",		4},
        { 6,    "mac",		5},
        { 6,    "mbp",		5},
        { 6,    "mba",		5},
        { 7,    "play station",	0},
        { 7,    "playstation",	0},
        { 7,    "xbox",		0},
        { 9,    "android",	1},
        { 9,    "htc",		1},
        { 9,    "miphone",	1},
        { 10,   "iphone",	5},
        { 10,   "ipod",		5},
        { 11,   "appletv",	5},
        { 11,   "apple tv",	5},
        { 11,   "apple-tv",	5},
        { 14,   "imac",		5},
        { 15,   "rog",		0},
        { 18,   "epson",	0},
        { 18,   "fuji xerox",	0},
        //{ 18,   "hp",		0},
        { 18,   "canon",	0},
        { 18,   "brother",	0},
        { 21,   "ipad",		5},
        { 22,   "linux",	3},
        { 24,   "rp-",		0},
        { 24,   "ea-",		0},
	{ 24,	"wmp-",		0},
	{ 27,	"chromecast",	0},
	{ 0,	NULL,		0}
};

struct _convType bwdpiTypes[] = {
        { 2,    "Wireless",		0},
	{ 2,    "Router",		0},
        { 2,    "Voip Gateway",		0},
        { 4,    "NAS",			0},
        { 5,    "IP Network Camera",	4},
        { 6,    "Mac OS",		5},
        { 7,    "Game Console",		0},
        { 9,    "Android Device",	1},
        { 9,    "Smartphone",		1},
        { 9,    "Voip Phone",		1},
        { 9,    "MiPhone",		1},
        { 10,   "Apple iOS Device",	5},
        { 10,   "iPhone",		5},
        { 11,   "Apple TV",		5},
        { 14,   "Macintosh",		5},
        { 18,   "Printer",		0},
        { 19,   "Windows Phone",	2},
        { 19,   "Nokia",		0},
        { 19,   "Windows Mobile",	2},
        { 20,   "Tablet",		1},
        { 21,   "iPad",			5},
        { 23,   "SmartTV",		0},
        { 25,   "Kindle",		0},
        { 25,   "Fire TV",		0},
        { 26,   "Scanner",		0},
        { 27,   "Chromecast",		0},
        { 28,   "ZenFone",		4},
        { 28,   "PadFone",		4},
        { 29,   "Asus Pad",		4},
        { 29,   "Asus ZenPad",		4},
        { 29,   "Transformer",		4},
        { 34,   "Desktop/Laptop",	0},
	{ 0,	NULL,			0}
};

struct _convType vendorTypes[] = {
	{ 0,	"ADOBE",		0},
	{ 0,	"Amazon",		0},
	{ 0,	"Apple",		5},
	{ 1,	"ASUS",			4},
	{ 1,	"Asus",			4},
	{ 0,	"BELKIN",		0},
	{ 0,	"Belkin",		0},
	{ 0,	"BizLink",		0},
	{ 0,	"BUFFALO",		0},
	{ 0,	"Dell",			0},
	//divide Dell and DellKing 
	{ 0,	"DellKing",		0},
	{ 0,	"D-Link",		0},
	//include suffix
	{ 0,	"FUJITSU",		0},
	{ 0,	"Fujitsu",		0},
	//disable when icon with vendor name
	//{ 0,	"NANJING FUJITSU",	0},
	{ 0,	"Google",		0},
	{ 0,	"HON HAI",		0},
	{ 0,	"Hon Hai",		0},
	{ 0,	"HTC",			0},
	{ 0,	"HUAWEI",		0},
	{ 0,	"Huawei",		0},
	{ 0,	"IBM",			0},
	//include suffix
	{ 0,	"Lenovo",		0},
	{ 0,	"NEC ",			0},
	//disable when icon with vendor name
	//{ 0,	"NECMagnus",		0},
	//{ 0,	"Wuhan NEC",		0},
    { 7,    "PS5",		    0},
	{ 0,	"MICROSOFT",	2},
	{ 0,	"Microsoft",	2},
	{ 30,	"MSFT 5.0",		2},
	{ 30,	"MSFT",			2},
    { 22,   "dhcpcd",		3},
    { 9,    "android",	1},
	{ 0,	"Panasonic",	0},
	{ 0,	"PANASONIC",	0},
	{ 0,	"PIONEER",		0},
	{ 0,	"Pioneer",		0},
	{ 0,	"Ralink",		0},
	{ 0,	"Samsung",		0},
	//{ 0,	"VD Division",		0},
	{ 0,	"SAMSUNG",		0},
	{ 0,	"Sony",			0},
	{ 0,	"Synology",		0},
	{ 0,	"TOSHIBA",		0},
	{ 0,	"Toshiba",		0},
	{ 0,	"TP-LINK",		0},
	//{ 0,	"Shenzhen Tp-Link",	0},
	{ 0,	"VMware",		0},
	{ 0,	NULL,			0}
};

ac_state *construct_ac_file(convType *type, const char * parse_filename)
{


	int i, lock, data_array_len = 0;

	unsigned int keywordLen;
	ac_state *allState, *state, *nextState, *newState;

	allState = create_ac_state();
	if(allState == NULL)
		return NULL;


	struct json_object *data_array = NULL;
	struct json_object *data_array_obj;
	struct json_object *array_keyword, *array_type, *array_os_type;


	if(check_if_file_exist(parse_filename)){

		lock = file_lock(parse_filename);
		data_array = json_object_from_file(parse_filename);
		file_unlock(lock);

		if(data_array) {
		  data_array_len = json_object_array_length(data_array);
		} else {
		  SM_DEBUG("%s >> parse [%s], data_array read error, %s \n", __FUNCTION__, parse_filename, json_object_get_string(data_array));
		  return NULL;
		}

	} else {
		SM_DEBUG("%s >> parse [%s], file not exist \n", __FUNCTION__, parse_filename);
		return NULL;
	}
	SM_DEBUG("%s >> parse [%s], data_array_len = %d\n", __FUNCTION__, parse_filename, data_array_len);

	int testi =0;
	for (i = 0; i < data_array_len; i++) {
		testi++;
		char data_keyword[128];
		unsigned char data_type;
		unsigned char data_os_type;

		// get the i-th object in data_array
		data_array_obj = json_object_array_get_idx(data_array, i);

		json_object_object_get_ex(data_array_obj, "keyword", &array_keyword);
		json_object_object_get_ex(data_array_obj, "type", &array_type);
		json_object_object_get_ex(data_array_obj, "os_type", &array_os_type);


		if(json_object_object_get_ex(data_array_obj, "keyword", &array_keyword)) {
			snprintf(data_keyword, 128, "%s", json_object_get_string(array_keyword));
		} else {
			continue;
		}
		if(json_object_object_get_ex(data_array_obj, "type", &array_type)) {
			data_type = json_object_get_int(array_type);
		} else {
			continue;
		}

		if(json_object_object_get_ex(data_array_obj, "os_type", &array_os_type)) {
			data_os_type = json_object_get_int(array_os_type);
		} else {
			data_os_type = 0;
		}

		SM_DEBUG("keyword[%d] = %s, type = %d, os_type = %d \n", i, data_keyword, data_type, data_os_type);

		int ii;

		keywordLen = strlen(data_keyword);
		
		// SM_DEBUG("keywordLen %d\n", keywordLen);

		for(state = allState, ii = 0; ii < keywordLen; ii++)
		{
			nextState = find_next_state(state, data_keyword[ii]);
			if(nextState == NULL) break;
			if(ii == (keywordLen - 1))
				add_match_rule_to_state(nextState, data_type, data_os_type);

			state = nextState;
		}

		for(; ii < keywordLen; ii++)
		{
			newState = create_ac_state();
			if(ii == (keywordLen - 1))
				add_match_rule_to_state(newState, data_type, data_os_type);
			
			add_new_next_state(state, data_keyword[ii], newState);
			state = newState;

			state->next = allState->next;
			allState->next = state;
		}	

	}
	
	return allState;
}


ac_state*
construct_ac_trie(convType *type)
{
	int i;
	unsigned int sigLen;
	convType *pType;
	ac_state *allState, *state, *nextState, *newState;

	allState = create_ac_state();
	if(allState == NULL)
		return NULL;

	for(pType = type; pType->signature; pType++)
  	{
		SM_DEBUG("##### %d %s\n", pType->type, pType->signature);
		sigLen = strlen(pType->signature);
		//SM_DEBUG("len %d\n", sigLen);
		for(state = allState, i = 0; i < sigLen; i++)
		{
			nextState = find_next_state(state, pType->signature[i]);
			if(nextState == NULL) break;
			if(i == (sigLen - 1))
				add_match_rule_to_state(nextState, pType->type, pType->base);

			state = nextState;
		}

		for(; i < sigLen; i++)
		{
			newState = create_ac_state();
			if(i == (sigLen - 1))
				add_match_rule_to_state(newState, pType->type, pType->base);
			
			add_new_next_state(state, pType->signature[i], newState);
			state = newState;

			state->next = allState->next;
			allState->next = state;
		}			
    }
	
	return allState;
}

ac_state*
find_next_state(ac_state *state, unsigned char transChar)
{
	// SM_DEBUG("find next state\n");
	ac_trans *ptrTrans;
	if(state->nextTrans != NULL)
	{
		for(ptrTrans = state->nextTrans; ptrTrans != NULL; ptrTrans = ptrTrans->nextTrans)
		{
			//SM_DEBUG("find state :%c\n", ptrTrans->transChar);
			if(transChar == ptrTrans->transChar){
				//SM_DEBUG("found state :%c\n", ptrTrans->transChar);
				return ptrTrans->nextState;
			}
		}
	}
	else
	{
		//SM_DEBUG("not found state\n");
		return NULL;
	}

	//SM_DEBUG("not found state\n");
	return NULL;
}

ac_state*
create_ac_state()
{
	//SM_DEBUG("create state\n");
	ac_state *state;
	state = (ac_state*)malloc(sizeof(ac_state));
	memset(state, 0, sizeof(ac_state));
	return state;
}

void
add_new_next_state(ac_state *curState, unsigned char pChar, ac_state *nextState)
{
	//SM_DEBUG("add next state\n");
	ac_trans *newTrans;
	newTrans = (ac_trans*)malloc(sizeof(ac_trans));
	newTrans->transChar = pChar;
	newTrans->nextState = nextState;
	newTrans->nextTrans = curState->nextTrans;
	curState->nextTrans = newTrans;
	nextState->prevState = curState;

	return;
}

void
add_match_rule_to_state(ac_state *state, unsigned char type, unsigned char base)
{
	//SM_DEBUG("add match rule\n");
	match_rule *newRule;
	newRule = (match_rule*)malloc(sizeof(match_rule));
	newRule->ID = type;
	newRule->baseID = base;
	newRule->next = state->matchRuleList;
	state->matchRuleList = newRule;

	return;
}

void
free_ac_state(ac_state *state)
{
	ac_state *ptrState;
	ac_trans *ptrTrans;
	match_rule *ptrMatchRule;
	while(state!=NULL)
	{
		ptrState = state;
		state = state->next;
		while(ptrState->nextTrans!=NULL)
		{
			ptrTrans = ptrState->nextTrans;
			ptrState->nextTrans = ptrState->nextTrans->nextTrans;
			free(ptrTrans);
		}
		while(ptrState->matchRuleList!=NULL)
		{
			ptrMatchRule = ptrState->matchRuleList;
			ptrState->matchRuleList = ptrState->matchRuleList->next;
			free(ptrMatchRule);
		}
		free(ptrState);
	}

	SM_DEBUG("free state machine success!\n");
	return;
}

unsigned char
prefix_search(ac_state *sm, const char *text, unsigned char *baseID)
{
	SM_DEBUG("Prefix search\n");
	int i;
	unsigned int textLen = strlen(text);
	SM_DEBUG("text length = %d:%s\n", textLen, text);

	ac_state *state, *curState;

	if(!(curState = find_next_state(sm, text[0]))) {
		SM_DEBUG("text[0] not match!! return 0\n");
		return 0;
	}

	for(i = 1; i < textLen; i++){
		state = curState;
		SM_DEBUG("search text[%d]: %c\n", i, text[i]);
		if(!(curState = find_next_state(curState, text[i]))) {
			if(state->matchRuleList) {
				*baseID = state->matchRuleList->baseID;
				return state->matchRuleList->ID;
			}
			else {
				SM_DEBUG("text[%d] not match!! return 0\n", i);
				return 0;
			}
		}
	}
	if(i == textLen)
	{
		if(curState->matchRuleList) {
			*baseID = curState->matchRuleList->baseID;
			return curState->matchRuleList->ID;
		}
		else {
			SM_DEBUG("end search not found pattern!! return 0\n");
			return 0;
		}
	}
	else
		return 0;
}

unsigned int
prefix_search_index(ac_state *sm, const char *text, unsigned char *baseID, unsigned char *typeID)
{
	SM_DEBUG("Prefix search index\n");
	int i;
	int search_index = 0;
	unsigned int textLen = strlen(text);
	SM_DEBUG("text length = %d:%s\n", textLen, text);

	ac_state *state, *curState;


	if(!(curState = find_next_state(sm, text[0]))) {
		SM_DEBUG("text[0] not match!! return 0\n");
		return 0;
	}

	for(i = 1; i < textLen; i++){
		search_index++;
		state = curState;
		SM_DEBUG("search text[%d]: %c\n", i, text[i]);
		if(!(curState = find_next_state(curState, text[i]))) {
			if(state->matchRuleList) {
				*baseID = state->matchRuleList->baseID;
				*typeID = state->matchRuleList->ID;
				return search_index + 1;
			}
			else {
				SM_DEBUG("text[%d] not match!! return 0\n", i);
				return 0;
			}
		}
	}

	if(i == textLen)
	{
		if(curState->matchRuleList) {
			*baseID = curState->matchRuleList->baseID;
			*typeID = curState->matchRuleList->ID;

			return search_index + 1;
		}
		else {
			SM_DEBUG("end search not found pattern!! return 0\n");
			return 0;
		}
	}
	else
		return 0;
}


unsigned char full_search(ac_state *sm, const char *text, unsigned char *baseID)
{
	SM_DEBUG("Full search\n");
	int i, j;
	unsigned int textLen = strlen(text);
	SM_DEBUG("text length = %d:%s\n", textLen, text);

	ac_state *state, *curState;


	for(i = 0; i < textLen - 1; i++){
		if(!(curState = find_next_state(sm, text[i]))) {
			SM_DEBUG("text[%d] not match!! search next\n", i);
			continue;
		}
		for(j = i + 1; j < textLen; j++){
			state = curState;
			SM_DEBUG("search text[%d]: %c\n", j, text[j]);
			if(!(curState = find_next_state(curState, text[j]))) {
				if(state->matchRuleList) {
					*baseID = state->matchRuleList->baseID;
					return state->matchRuleList->ID;
				}
				else {
					SM_DEBUG("text[%d] not match!! search initial state\n", j);
					break;
				}
			}
			
			if(j == textLen -1){
				if(curState->matchRuleList) {
					*baseID = curState->matchRuleList->baseID;
					return curState->matchRuleList->ID;
				}
				else{
					SM_DEBUG("end search not found pattern!! return 0\n");
					return 0;
				}
			}
		}
	}

	SM_DEBUG("end search not found pattern!! return 0\n");
	return 0;
}