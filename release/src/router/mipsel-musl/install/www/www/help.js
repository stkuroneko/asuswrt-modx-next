var Untranslated = {
fw_size_higher_mem : 'Memory space is NOT enough to upgrade on internet. Please wait for rebooting.',
ASUSGATE_note9 : 'Your DSL line appears to be unstable. DLA (Dynamic Line Adjustment) which enabled by default already adopted necessary changes and ensure stability. However, if interruption continues please submit a Feedback form with "Enable DSL Line Diagnostic" option set as "Yes" and "Diagnostic debug log capture duration" set as 24 hours for our analysis(no need to enable System diagnostic).',
ASUSGATE_note6 : "Your DSL (Digital Suscriber Line) seems unstable. We strongly recommend that you submit feedback to our support team.",
ASUSGATE_note7 : "If you are experiencing any DSL related issues or you have any comments, please feel free to inform our support team.",
ASUSGATE_act_feedback : "Feedback now",
ASUSGATE_DSL_setting : "Go setting DSL"
};
var rc_support = '<% nvram_get("rc_support"); %>';
var gobi_support = (rc_support.search("gobi") == -1) ? false : true;
var secure_default = (rc_support.search("secure_default") == -1) ? false : true;
/* convert some special character for shown string */
function handle_show_str(show_str)
{
show_str = show_str.replace(/\&/g, "&amp;");
show_str = show_str.replace(/\</g, "&lt;");
show_str = show_str.replace(/\>/g, "&gt;");
show_str = show_str.replace(/\ /g, "&nbsp;");
return show_str;
}
function show_str_ssid(show_ssid)
{
show_ssid = show_ssid.replace(/\%/g, "%25");
return show_ssid;
}
function isMobile_help(){
return false; //disable mobile QIS temporary, Jieming added at 2013.08.12
if(screen.width < 640 || screen.height < 640){
return true;
}
else{
var mobiles = new Array(
"midp", "j2me", "avant", "docomo", "novarra", "palmos", "palmsource",
"240x320", "opwv", "chtml", "pda", "windows ce", "mmp/",
"blackberry", "mib/", "symbian", "wireless", "nokia", "hand", "mobi",
"phone", "cdm", "up.b", "audio", "sie-", "sec-", "samsung", "htc",
"mot-", "mitsu", "sagem", "sony", "alcatel", "lg", "eric", "vx",
"NEC", "philips", "mmm", "xx", "panasonic", "sharp", "wap", "sch",
"rover", "pocket", "benq", "java", "pt", "pg", "vox", "amoi",
"bird", "compal", "kg", "voda", "sany", "kdd", "dbt", "sendo",
"sgh", "gradi", "jb", "dddi", "moto", "iphone", "android",
"iPod", "incognito", "webmate", "dream", "cupcake", "webos",
"s8000", "bada", "googlebot-mobile");
var ua = navigator.userAgent.toLowerCase();
var _isMobile = false;
for(var i = 0; i < mobiles.length; i++){
if(ua.indexOf(mobiles[i]) > 0){
_isMobile = true;
break;
}
}
return _isMobile;
}
}
var helptitle = new Array();
var helpcontent = new Array();
(function(){
if(!isMobile_help()){
setTimeout(function(){
var newScript = document.createElement("script");
newScript.type = "text/javascript";
newScript.src = '/help_content.js';
document.getElementsByTagName("head")[0].appendChild(newScript);
}, 2000);
}
})();
function suspendconn(wan_index, wanenable){
if(gobi_support && (wan_index == usb_index)){
document.internetForm_title.wan_enable.value = wanenable;
document.internetForm_title.wan_unit.value = wan_index;
}
else if(wan_index == dsl_index) {
document.internetForm_title.dslx_link_enable.value = wanenable;
if(wanenable)
document.internetForm_title.action_script.value = "start_dslwan_if 0";
else
document.internetForm_title.action_script.value = "stop_dslwan_if 0";
}
else{
document.internetForm_title.wan_enable.value = wanenable;
}
showLoading();
document.internetForm_title.submit();
}
function enableMonomode(){
document.titleForm.action = "/apply.cgi";
document.titleForm.current_page.value = top.location.pathname.split("/")[1];
document.titleForm.action_mode.value = "mfp_monopolize";
document.titleForm.action_wait.value = "2";
showLoading(2);
document.titleForm.submit();
}
function remove_all_disk(){
var str = "<#3325#>";
if(confirm(str)){
showLoading();
document.diskForm_title.disk.value = "all";
setTimeout(function(){
document.diskForm_title.submit();
}, 1);
}
}
function remove_disk(disksIndex){
require(['/require/modules/diskList.js?hash=' + Math.random().toString()], function(diskList){
var removeHandler = function(disk){
var str = "";
str += (disk.isBusy) ? "<#1499#> ".split(":")[1] : "" ;
str += "<#3325#>";
if(confirm(str)){
parent.showLoading();
document.diskForm_title.disk.value = disk.node;
setTimeout(function(){
document.diskForm_title.submit();
}, 1);
}
}
var usbDevicesList = diskList.list();
for(var i=0; i < usbDevicesList.length; i++){
if(usbDevicesList[i].node == disksIndex){
removeHandler(usbDevicesList[i]);
break;
}
}
});
}
function gotoguestnetwork(){
top.location.href = "/Guest_network.asp";
}
function gotocooler(){
top.location.href = "/Advanced_PerformanceTuning_Content.asp";
}
function priority_change(){
top.location.href = "/QoS_EZQoS.asp";
}
function qos_disable(){
document.qosDisableForm.submit();
}
function gotoDSL_log(){
top.location.href = "/Main_AdslStatus_Content.asp";
}
function gotoModem(){
if(dualWAN_support){
document.titleForm.wan_unit.disabled = false;
document.titleForm.wan_unit.value = usb_index;
if( usb_index == -1){
top.location.href = "/Advanced_WANPort_Content.asp";
}
else{
if(gobi_support)
document.titleForm.current_page.value = "Advanced_MobileBroadband_Content.asp?af=pincode";
else
document.titleForm.current_page.value = "Advanced_Modem_Content.asp";
document.titleForm.action_mode.value = "change_wan_unit";
document.titleForm.action = "apply.cgi";
document.titleForm.target = "";
document.titleForm.submit();
}
}
else{
top.location.href = "/Advanced_Modem_Content.asp";
}
}
function setTrafficLimit(){
document.titleForm.wan_unit.disabled = false;
document.titleForm.wan_unit.value = usb_index;
document.titleForm.current_page.value = "Advanced_MobileBroadband_Content.asp?af=data_limit;show=0";
document.titleForm.action_mode.value = "change_wan_unit";
document.titleForm.action = "apply.cgi";
document.titleForm.target = "hidden_frame";
document.titleForm.submit();
}
function upated_sim_record(){ //delete the oldest record and save the current data usage settings
document.titleForm.sim_order.disabled = false;
document.titleForm.current_page.value = "Advanced_MobileBroadband_Content.asp";
document.titleForm.action_mode.value = "restart_sim_del";
document.titleForm.sim_order.value = "1";
document.titleForm.action = "apply.cgi";
document.titleForm.target = "";
document.titleForm.submit();
}
var debug_end_time = parseInt("<% nvram_get("dslx_diag_end_uptime"); %>");
var wans_mode = '<%nvram_get("wans_mode");%>';
var wans_lanport = '<% nvram_get("wans_lanport"); %>';
var orig_wanports_bond = '<% nvram_get("wanports_bond"); %>';
function overHint(itemNum){
var statusmenu = "";
var title2 = 0;
var title5 = 0;
var title5_2 = 0;
if(itemNum == 101){
statusmenu ="<span><#4049#></span>";
}
else if(itemNum == 102){
statusmenu ="<span><#4050#></span>".replace(/LAN-*\D* 4/, wanAggr_p2_name(orig_wanports_bond));
}
if(itemNum == 50){
statusmenu ="<span><#714#></span>";
}
if(itemNum == 85){
statusmenu ="<span><#1018#></span>";
}
else if(itemNum == 86){
statusmenu ="<span><#1021#><br><#1010#></span>";
}
else if(itemNum == 87){
statusmenu ="<span><#1033#><br><#1011#></span>";
}
else if(itemNum == 88){
statusmenu ="<span><#1035#><br><#1013#></span>";
}
else if(itemNum == 89){
statusmenu ="<span>Enable this function allow block advertisement in the streaming video.</span>";
}
else if(itemNum == 90){
statusmenu ="<span>Enable this function allow you to block websites used to display banner or popup advertisement.</span>";
}
else if(itemNum == 91){
statusmenu ="<span><#1010#></span>";
}
else if(itemNum == 92){
statusmenu ="<span><#1011#></span>";
}
else if(itemNum == 93){
statusmenu ="<span><#1012#></span>";
}
else if(itemNum == 94){
statusmenu ="<span><#1013#></span>";
}
else if(itemNum == 95){
statusmenu ="<span><#1014#></span>";
}
else if(itemNum == 96){
statusmenu ="<span><#1015#></span>";
}
else if(itemNum == 97){
statusmenu ="<span><#1016#></span>";
}
else if(itemNum == 103){
statusmenu ="<span><#1038#></span>";
}
else if(itemNum == 104){
statusmenu ="<span><#1037#></span>";
}
if(itemNum == 98){
var signal = parseInt(sim_signal);
if(isNaN(signal) || signal <= 0){
statusmenu += "<div class='StatusHint'><#2937#></div>";
}
else if(usb_state == 2 && usb_sbstate == 0 && usb_auxstate != 1){
statusmenu += "<div class='StatusHint'><#280#> <#2502#>: </div><span>" + decodeURIComponent(modem_act_provider) + "</span>";
}
else{
statusmenu += "<div class='StatusHint'><#311#></div>";
}
}
if(itemNum == 99){
if(sim_state == "1")
statusmenu += "<div class='StatusHint'><#2967#></div>";
else if(sim_state == "2"){
if( g3err_pin == "1" && pin_remaining_count < 3)
statusmenu += "<div class='StatusHint'>Wrong PIN code. Please input the correct PIN code.</div>";
else
statusmenu += "<div class='StatusHint'><#2928#></div>";
}
else if(sim_state == "3")
statusmenu += "<div class='StatusHint'><#2930#></div>";
else if(sim_state == "4")
statusmenu += "<div class='StatusHint'><#2929#></div>";
else if(sim_state == "5")
statusmenu += "<div class='StatusHint'><#2931#></div>";
else if(sim_state == "6")
statusmenu += "<div class='StatusHint'><#2989#></div>";
else if(sim_state == "-1")
statusmenu += "<div class='StatusHint'><#2964#></div>";
else if(sim_state == "-10" || sim_state == "-2")
statusmenu += "<div><#2962#></div>";
else
statusmenu += "<div><#2906#></div>";
}
if(itemNum == 24)
statusmenu += "<span>The USB 3.0 cable without well-shielded would affect the 2.4Ghz wireless range.Enabling this feature to ensure the best wireless performance If your USB 3.0 device is not USB-IF certified.</span>";
if(itemNum == 25)
statusmenu += "<span><#1414#></span>";
else if(itemNum == 23)
statusmenu += "<span><#1413#></span>";
else if(itemNum == 22)
statusmenu += "<span><#1412#></span>";
else if(itemNum == 21)
statusmenu += "<span><#1411#></span>";
else if(itemNum == 20)
statusmenu += "<span><#1410#></span>";
else if(itemNum == 19)
statusmenu += "<span><#1409#></span>";
else if(itemNum == 18)
statusmenu += "<span><#1408#></span>";
else if(itemNum == 17)
statusmenu += "<span><#1407#></span>";
else if(itemNum == 16)
statusmenu += "<span><#1406#></span>";
else if(itemNum == 15)
statusmenu += "<span><#1405#></span>";
else if(itemNum == 14)
statusmenu += "<span><#1404#></span>";
else if(itemNum == 13)
statusmenu += "<span><#1403#></span>";
else if(itemNum == 12)
statusmenu += "<span><#1402#></span>";
else if(itemNum == 11)
statusmenu += "<span><#1401#></span>";
else if(itemNum == 10)
statusmenu += "<span><#1400#></span>";
if(itemNum == 26)
statusmenu += "<span><#3260#></span>";
if(itemNum == "A"){
statusmenu = "<div class='StatusHint'><#1027#> :</div>";
if(bwdpi_app_rulelist.indexOf('game') != -1){
modeDesc = "<#1374#>"; /* untranslated */
}
else if(bwdpi_app_rulelist.indexOf('media') != -1){
modeDesc = "<#1375#>"; /* untranslated */
}
else if(bwdpi_app_rulelist.indexOf('web') != -1){
modeDesc = "<#1034#>"; /* untranslated */
}
else if(bwdpi_app_rulelist.indexOf('eLearning') != -1){
modeDesc = "<#1036#>"; /* untranslated */
}
else if(bwdpi_app_rulelist.indexOf('videoConference') != -1){
modeDesc = "<#1024#>"; /* untranslated */
}
else{
modeDesc = "<#1832#>"; /* untranslated */
}
statusmenu += "<span>" + modeDesc + "</span>";
}
if(itemNum == 27){ //Feedback Diagnostic
if(diag_dblog_enable == "1") {
var lineDesc = "";
statusmenu = "<div class='StatusHint'>System Diagnostic :</div>"; /* untranslated */
lineDesc = "<#2104#><br>";
statusmenu += "<span>" + lineDesc + "</span>";
statusmenu += "<div class='StatusHint'><#1664#> :</div>";
lineDesc = ""; /* Untranslated */
var transform_dblog_service = function() {
var dblog_service = parseInt('<% nvram_get("dblog_service"); %>');
var dblog_service_mapping = ["", "WiFi", "<#1938#>", "<#901#>", "AiMesh"];/* untranslated */
var dblog_service_text = "";
for(var i = 1; dblog_service != 0 && i <= 4; i++) {
if(dblog_service & 1) {
if(dblog_service_text != "")
dblog_service_text += ", " + dblog_service_mapping[i];
else
dblog_service_text += dblog_service_mapping[i];
}
dblog_service = dblog_service >> 1;
}
return dblog_service_text;
};
lineDesc += transform_dblog_service();
statusmenu += "<span>" + lineDesc + "</span>";
statusmenu += "<div class='StatusHint'><#3003#> :</div>";
lineDesc = ""; /* Untranslated */
var transform_dblog_remaining = function() {
var dblog_remaining = parseInt(diag_dblog_remaining);
var days = Math.floor(dblog_remaining / 60 / 60 / 24);
var hours = Math.floor(dblog_remaining / 60 / 60 % 24);
var minutes = Math.floor(dblog_remaining / 60 % 60);
var seconds = Math.floor(dblog_remaining % 60);
var remaining_time_str = "";
if(dblog_remaining == 0) {
remaining_time_str += "0" + " <#3348#> ";
return remaining_time_str;
}
if(days)
remaining_time_str += days + " <#1841#> ";
if(hours)
remaining_time_str += hours + " <#2487#> ";
if(minutes)
remaining_time_str += minutes + " <#2893#> ";
if(seconds)
remaining_time_str += seconds + " <#3348#> ";
return remaining_time_str;
};
lineDesc += transform_dblog_remaining();
statusmenu += "<span>" + lineDesc + "</span>";
}
}
if(itemNum == 9){
var lineDesc = "";
statusmenu = "<div class='StatusHint'>DSL :</div>";
if(wan_line_state == "up")
lineDesc += "Link up";
else if(wan_line_state == "wait for init")
lineDesc += "Wait for init";
else if(wan_line_state == "init" || wan_line_state == "initializing")
lineDesc += "Initializing";
else
lineDesc += "Link down";
if(wan_diag_state == "1" && allUsbStatus.search("storage") >= 0){
lineDesc += "<br><#2104#><br>";
lineDesc += show_diagTime(boottime_update);
}
statusmenu += "<span>" + lineDesc + "</span>";
}
if(itemNum == 8){
statusmenu = "<div class='StatusHint'>WiFi :</div>";
if(wl_info.band5g_2_support){
if(wlan0_radio_flag == "0")
wifiDesc = "<b>2.4GHz -</b> <#1663#>";
else
wifiDesc = "<b>2.4GHz -</b> <#1664#>";
if(wlan1_radio_flag == "0")
wifiDesc += "<br><br><b>5GHz-1 -</b> <#1663#>";
else
wifiDesc += "<br><br><b>5GHz-1 -</b> <#1664#>";
if(wlan2_radio_flag == "0")
wifiDesc += "<br><br><b>5GHz-2 -</b> <#1663#>";
else
wifiDesc += "<br><br><b>5GHz-2 -</b> <#1664#>";
statusmenu += "<span>" + wifiDesc + "</span>";
}
else if(wl_info.band5g_support){
if(wlan0_radio_flag == "0" && wlan1_radio_flag == "0")
wifiDesc = "<b>2.4GHz -</b><br><#1663#><br><br><b>5 GHz -</b><br><#1663#>";
else if(wlan0_radio_flag == "1" && wlan1_radio_flag == "0")
wifiDesc = "<b>2.4GHz -</b><br><#1664#><br><br><b>5 GHz -</b><br><#1663#>";
else if(wlan0_radio_flag == "0" && wlan1_radio_flag == "1")
wifiDesc = "<b>2.4GHz -</b><br><#1663#><br><br><b>5 GHz -</b><br><#1664#>";
else
wifiDesc = "<b>2.4GHz -</b><br><#1664#><br><br><b>5 GHz -</b><br><#1664#>";
statusmenu += "<span>" + wifiDesc + "</span>";
}
else{
if(wlan0_radio_flag == "0")
wifiDesc = "<#1663#>";
else
wifiDesc = "<#1664#>";
statusmenu += "<span>" + wifiDesc + "</span>";
}
}
if(itemNum == 7){
statusmenu = "<div class='StatusHint'>Cooler:</div>";
if(cooler == "cooler=0")
coolerDesc = "cooler=Disabled"
else if(cooler == "cooler=1")
coolerDesc = "cooler=Manually"
else
coolerDesc = "cooler=Automatic"
statusmenu += "<span>" + coolerDesc.substring(7, coolerDesc.length) + "</span>";
}
if(itemNum == 6){
require(['/require/modules/diskList.js'], function(diskList){
var usbDevicesList = diskList.list();
for(var i=0; i<usbDevicesList.length; i++){
if(usbDevicesList[i].deviceType != "printer") continue;
statusmenu += "<div class='StatusHint' style='margin-top:8px'>" + usbDevicesList[i].deviceName + ":</div>";
if(usbDevicesList[i].serialNum == '<% nvram_get("u2ec_serial"); %>'){
statusmenu += "<div><#1806#></div>";
if(monoClient != "monoClient=")
statusmenu += "<div><#3228#>" + monoClient.substring(11, monoClient.length) + "</div>";
}
else
statusmenu += "<div><#1803#></div>";
}
if(statusmenu != "")
return overlib(statusmenu, OFFSETX, -160, LEFT, DELAY, 400);
});
}
if(itemNum == 5){
statusmenu = "<span class='StatusHint'><#3064#></span>";
}
if(itemNum == 4){
for(var i=0; i<gn_array_2g.length; i++){
if(gn_array_2g[i][0] == 1){
if(title2 == 0){
statusmenu += "<div class='StatusHint'>2.4GHz Network:</div>";
title2 = 1;
}
var show_str = gn_array_2g[i][1];
show_str = decodeURIComponent(show_str);
show_str = handle_show_str(show_str);
statusmenu += "<span><b>" + show_str + "</b><br> (";
if(gn_array_2g[i][11] == 0)
statusmenu += "<#2836#>)</span><br>";
else{
var expire_day = Math.floor(gn_array_2g[i][13]/86400);
var expire_hr = Math.floor((gn_array_2g[i][13]%86400)/3600);
var expire_min = Math.floor((gn_array_2g[i][13]%3600)/60);
statusmenu += '<#3003#>: ';
if(expire_day > 0)
statusmenu += '<b id="expire_day_'+i+'">'+ expire_day + '</b> <#1841#> <b id="expire_hr_'+i+'">'+ expire_hr + '</b> <#2487#> <b id="expire_min_'+i+'">' + expire_min +'</b> <#2893#>';
else if(expire_hr > 0)
statusmenu += '<b id="expire_hr_'+i+'">'+ expire_hr + '</b> <#2487#> <b id="expire_min_'+i+'">' + expire_min +'</b> <#2893#>';
else{
if(expire_min > 0)
statusmenu += '<b id="expire_min_'+i+'">' + expire_min +'</b> <#2893#>';
else
statusmenu += '<b id="expire_min_'+i+'">< 1</b> <#2893#>';
}
statusmenu += ")</span><br>";
}
}
}
if(band5g_support){
for(var i=0; i<gn_array_5g.length; i++){
if(gn_array_5g[i][0] == 1){
if(title5 == 0){
if(wl_info.band5g_2_support)
statusmenu += "<div class='StatusHint' style='margin-top:15px;'>5GHz-1 Network:</div>";
else
statusmenu += "<div class='StatusHint' style='margin-top:15px;'>5GHz Network:</div>";
title5 = 1;
}
var show_str = gn_array_5g[i][1];
show_str = decodeURIComponent(show_str);
show_str = handle_show_str(show_str);
statusmenu += "<span><b>" + show_str + "</b><br> (";
if(gn_array_5g[i][11] == 0)
statusmenu += '<#2836#>)</span><br>';
else{
var expire_day = Math.floor(gn_array_5g[i][13]/86400);
var expire_hr = Math.floor((gn_array_5g[i][13]%86400)/3600);
var expire_min = Math.floor((gn_array_5g[i][13]%3600)/60);
statusmenu += '<#3003#>: ';
if(expire_day > 0)
statusmenu += '<b id="expire_day_'+i+'">'+ expire_day + '</b> <#1841#> <b id="expire_hr_'+i+'">'+ expire_hr + '</b> <#2487#> <b id="expire_min_'+i+'">' + expire_min +'</b> <#2893#>';
else if(expire_hr > 0)
statusmenu += '<b id="expire_hr_'+i+'">'+ expire_hr + '</b> <#2487#> <b id="expire_min_'+i+'">' + expire_min +'</b> <#2893#>';
else{
if(expire_min > 0)
statusmenu += '<b id="expire_min_'+i+'">' + expire_min +'</b> <#2893#>';
else
statusmenu += '<b id="expire_min_'+i+'">< 1</b> <#2893#>';
}
statusmenu += ")</span><br>";
}
}
}
}
if(wl_info.band5g_2_support || wl_info.band6g_support){
for(var i=0; i<gn_array_5g_2.length; i++){
if(gn_array_5g_2[i][0] == 1){
if(title5_2 == 0){
if(band6g_support){
statusmenu += "<div class='StatusHint' style='margin-top:15px;'>6 GHz Network:</div>";
}
else{
statusmenu += "<div class='StatusHint' style='margin-top:15px;'>5 GHz-2 Network:</div>";
}
title5_2 = 1;
}
var show_str = gn_array_5g_2[i][1];
show_str = decodeURIComponent(show_str);
show_str = handle_show_str(show_str);
statusmenu += "<span><b>" + show_str + "</b><br> (";
if(gn_array_5g_2[i][11] == 0)
statusmenu += '<#2836#>)</span><br>';
else{
var expire_day = Math.floor(gn_array_5g_2[i][13]/86400);
var expire_hr = Math.floor((gn_array_5g_2[i][13]%86400)/3600);
var expire_min = Math.floor((gn_array_5g_2[i][13]%3600)/60);
statusmenu += '<#3003#>: ';
if(expire_day > 0)
statusmenu += '<b id="expire_day_'+i+'">'+ expire_day + '</b> <#1841#> <b id="expire_hr_'+i+'">'+ expire_hr + '</b> <#2487#> <b id="expire_min_'+i+'">' + expire_min +'</b> <#2893#>';
else if(expire_hr > 0)
statusmenu += '<b id="expire_hr_'+i+'">'+ expire_hr + '</b> <#2487#> <b id="expire_min_'+i+'">' + expire_min +'</b> <#2893#>';
else{
if(expire_min > 0)
statusmenu += '<b id="expire_min_'+i+'">' + expire_min +'</b> <#2893#>';
else
statusmenu += '<b id="expire_min_'+i+'">< 1</b> <#2893#>';
}
statusmenu += ")</span><br>";
}
}
}
}
if(title2 == 0 && title5 == 0 && title5_2 == 0)
statusmenu += "<div class='StatusHint'><#377#>:</div><span><#1803#></span>";
}
if(itemNum == 3){
var eLAN_str = "<#2050#>".replace(/WAN/, "LAN");
(function(){
var wans_mode = '<%nvram_get("wans_mode");%>';
var connect_obj = function(_link_status, _link_sbstatus, _link_auxstatus, unit){
if(dualwan_enabled && active_wan_unit != unit && (wans_mode == "fo" || wans_mode == "fb")){
this.hint = "<#3473#>";
}
else{
this.hint = "<#311#>";
}
if(_link_status == "1"){
this.hint = "<#939#>";
}
else if(_link_status == "2" && _link_sbstatus == "0"){
if(dualwan_enabled && active_wan_unit != unit && (wans_mode == "fo" || wans_mode == "fb")){
this.hint = "<#3474#>";
}
else if(link_internet == "2"){
this.hint = "<#280#>";
}
}
else{
if(sw_mode == 1){
_wan_enable = (unit == 0)? wan0_enable : wan1_enable;
if( wans_dualwan_array[unit] == "usb"){
if(_wan_enable == "0"){
if(gobi_support)
this.hint = "<#2904#>";
else
this.hint = "<#3743#>";
}
else{
if(sim_state != "" && sim_state != "1"){
if(sim_state == "2"){
if( g3err_pin == "1" && pin_remaining_count < 3)
this.hint = "Wrong PIN code. Please input the correct PIN code.";
else
this.hint = "<#2928#>";
}
else if(sim_state == "3")
this.hint = "<#2930#>";
else if(sim_state == "4")
this.hint = "<#2929#>";
else if(sim_state == "5")
this.hint = "<#2931#>";
else if(sim_state == "6")
this.hint = "<#2989#>";
else if(sim_state == "-1")
this.hint = "<#2964#>";
else if(sim_state == "-10" || sim_state == "-2")
this.hint = "<#2962#>";
else
this.hint = "<#2906#>";
}
}
}
else{
if(_wan_enable == 0){
this.hint = "<#3982#>";
}
else{
if(_link_auxstatus == "1"){
if( wans_dualwan_array[unit] == "lan"){
this.hint = "<#1675#> : <#3161#> "+wans_lanport;
}
else
this.hint = "<#3250#>";
}
else if(_link_sbstatus == "1")
this.hint = "<#941#>";
else if(_link_sbstatus == "2")
this.hint = "<#815#>";
else if(_link_sbstatus == "3")
this.hint = "<#814#>";
else if(_link_sbstatus == "4")
this.hint = "<#944#>";
else if(_link_sbstatus == "5")
this.hint = "<#943#>";
else if(_link_sbstatus == "6")
this.hint = "System error. <#3257#>";
}
}
}
else if(sw_mode == 2 || sw_mode == 4){
if(_wlc_state == "wlc_state=2"){
this.hint = "<span><#119#></span><br><br>";
if(wlc_band == 0)
this.hint += "<b>Link rate: </b>"+ data_rate_info_2g;
else if(wlc_band == 1)
this.hint += "<b>Link rate: </b>"+ data_rate_info_5g;
else if(wlc_band == 2)
this.hint += "<b>Link rate: </b>"+ data_rate_info_5g_2;
if(!Rawifi_support && !Qcawifi_support) {
this.hint += "<br><br>";
if(wlc_band == 0)
this.hint += "<b>RSSI: </b>"+ rssi_2g;
else if(wlc_band == 1)
this.hint += "<b>RSSI: </b>"+ rssi_5g;
else if(wlc_band == 2)
this.hint += "<b>RSSI: </b>"+ rssi_5g_2;
}
}
else{
if(_wlc_sbstate == "wlc_sbstate=2")
this.hint = "<#109#>";
else
this.hint ="<#108#>";
}
}
}
return this;
}
if(dualwan_enabled){
var connect_status = {
primary: new connect_obj(first_link_status, first_link_sbstatus, first_link_auxstatus, 0),
secondary: new connect_obj(secondary_link_status, secondary_link_sbstatus, secondary_link_auxstatus, 1)
};
statusmenu = "<div class='StatusHint'><#2015#>:</div>";
if( wans_dualwan_array[0] == "wan")
statusmenu += "<b><#2050#> - </b><br>";
else if( wans_dualwan_array[0] == "lan")
statusmenu += "<div class='StatusHint'>"+eLAN_str+" (<#3161#> "+wans_lanport+") - </div>";
else if( wans_dualwan_array[0] == "usb"){
if(gobi_support)
statusmenu += "<div class='StatusHint'><#2977#> - </div>";
else
statusmenu += "<b><#508#> - </b><br>";
}
statusmenu += "<span>" + connect_status.primary.hint + "</span>";
statusmenu += "<div class='StatusHint'><br><#2022#>:</div>";
if( wans_dualwan_array[1] == "wan")
statusmenu += "<b><#2050#> - </b><br>";
else if( wans_dualwan_array[1] == "lan")
statusmenu += "<div class='StatusHint'>"+eLAN_str+" (<#3161#> "+wans_lanport+") - </div>";
else if( wans_dualwan_array[1] == "usb"){
if(gobi_support)
statusmenu += "<div class='StatusHint'><#2977#> - </div>";
else
statusmenu += "<b><#508#> - </b><br>";
}
statusmenu += "<span>" + connect_status.secondary.hint + "</span>";
}
else{
var connect_status = new connect_obj(link_status, link_sbstatus, link_auxstatus, 0);
statusmenu = "<div class='StatusHint'><#3487#>:</div>";
if( wans_dualwan_array[0] == "wan")
statusmenu += "<b><#2050#> - </b><br>";
else if( wans_dualwan_array[0] == "lan")
statusmenu += "<div class='StatusHint'>"+eLAN_str+" (<#3161#> "+wans_lanport+") - </div>";
else if( wans_dualwan_array[0] == "usb"){
if(gobi_support)
statusmenu += "<div class='StatusHint'><#2977#> - </div>";
else
statusmenu += "<b><#508#> - </b><br>";
}
statusmenu += "<span>" + connect_status.hint + "</span>"
}
})();
}
if(itemNum == 2){
require(['/require/modules/diskList.js'], function(diskList){
var usbDevicesList = diskList.list();
statusmenu = "";
for(var i=0; i<usbDevicesList.length; i++){
if(usbDevicesList[i].deviceType == "printer") continue;
statusmenu += "<div class='StatusHint' style='margin-top:8px'>" + usbDevicesList[i].deviceName + ":</div>";
statusmenu += "<div>" + usbDevicesList[i].deviceType.charAt(0).toUpperCase() + usbDevicesList[i].deviceType.substring(1).toLowerCase() + "</div>";
if(usbDevicesList[i].deviceType == "storage" && usbDevicesList[i].mountNumber == 0)
statusmenu += "<div><#1893#></div>";
else if(usbDevicesList[i].hasErrPart)
statusmenu += "<div><#1896#></div>";
else{
if(usbDevicesList[i].hasAppDev)
statusmenu += "<div><#504#></div>";
if(usbDevicesList[i].hasTM)
statusmenu += "<div>Time Machine</div>";
}
}
if( statusmenu == "" )
statusmenu = "<div class='StatusHint'><#3065#></div>";
return overlib(statusmenu, OFFSETX, -160, LEFT, DELAY, 400);
});
}
if( statusmenu != "" )
return overlib(statusmenu, OFFSETX, -160, LEFT, DELAY, 400);
}
function show_diagTime(boottime_update){
Etime = debug_end_time - boottime_update;
EHours = Math.floor(Etime / 3600);
EMinutes = Math.floor(Etime % 3600 / 60);
if(EHours <= 0 && EMinutes <= 0)
return "<#3003#> : <span>0</span> <#2487#> <span>0</span> <#2893#>";
else
return "<#3003#> : <span>"+EHours+"</span> <#2487#> <span>"+EMinutes+"</span> <#2893#>";
}
function cancel_diag(){
parent.document.canceldiagForm.submit();
}
function cancel_dblog(){
parent.document.canceldblogForm.submit();
}
function openHint(hint_array_id, hint_show_id, flag){
statusmenu = "";
if(hint_array_id == 24){
var _caption = "";
if(hint_show_id == 10){ // Feedback System Diagnostic Capture
statusmenu = "<span class='StatusClickHint' onclick='cancel_dblog();' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'><#2103#></span>";
_caption = "System Diagnostic capture";
}
else if(hint_show_id == 9){ //2015.07 Viz add for bwdpi : Adaptive QoS mode
statusmenu = "<span class='StatusClickHint' onclick='priority_change();' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'><#1017#></span><br>";
statusmenu += "<span class='StatusClickHint' onclick='qos_disable();' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'><#2064#></span>";
_caption = "<#1027#>";
}
else if(hint_show_id == 8){ //2014.10 Viz add for dsl dslx_diag_state
statusmenu = "<span class='StatusClickHint' onclick='cancel_diag();' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'><#2103#></span>";
_caption = "DSL Line Diagnostic capture";
}
else if(hint_show_id == 7){
statusmenu = "<span class='StatusClickHint' onclick='gotoModem();' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'>";
if(dualWAN_support){
if(usb_index == -1){
statusmenu += "<#1008#></span>"
_caption = "<#315#>";
}
else{
if(gobi_support){
statusmenu += "<#2960#></span>"
_caption = "<#2977#>";
}
else{
statusmenu += "<#2408#></span>"
_caption = "<#508#>";
}
}
}
else{
statusmenu += "<#2408#></span>"
_caption = "<#508#>";
}
}
else if(hint_show_id == 6){ // Viz add 2013.04 for dsl sync status
statusmenu = "<span class='StatusClickHint' onclick='gotoDSL_log();' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'>Go to DSL Log</span>";
_caption = "DSL Log";
}
else if(hint_show_id == 5){
statusmenu = "<span class='StatusClickHint' onclick='gotocooler();' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'><#2075#></span>";
_caption = "Perfomance Tuning";
}
else if(hint_show_id == 4){
statusmenu = "<span class='StatusClickHint' onclick='gotoguestnetwork();' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'><#2407#></span>";
_caption = "Guest Network";
}
else if(hint_show_id == 3){
var eLAN_str = "<#2050#>".replace(/WAN/, "LAN");
if(sw_mode == 1){
if(!dualWAN_support || wans_dualwan_array[1] == "none"){
if((link_status == "2" && link_auxstatus == "0") || (link_status == "2" && link_auxstatus == "2"))
statusmenu = "<span class='StatusClickHint' onclick='suspendconn(0, 0);' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'><#1892#></span>";
else{
statusmenu = "<span class='StatusClickHint' onclick='goToWAN(0);' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'>";
if(usb_index == 0){
if(gobi_support)
statusmenu += "<#2960#></span>";
else
statusmenu += "<#2408#></span>";
}
else
statusmenu += "<#3996#></span>";
}
}
else{
if(gobi_support){
if( wans_dualwan_array[0] == "wan")
statusmenu += "<div class='StatusHint'><#2050#>:</div>";
else if( wans_dualwan_array[0] == "lan")
statusmenu += "<div class='StatusHint'>"+eLAN_str+" (<#3161#> "+wans_lanport+"):</div>";
else if( wans_dualwan_array[0] == "usb")
statusmenu += "<div class='StatusHint'><#2977#>:</div>";
}
else{
statusmenu = "<div class='StatusHint'><#2015#>:</div>";
if( wans_dualwan_array[0] == "wan")
statusmenu += "<b><#2050#> -</b><br>";
else if( wans_dualwan_array[0] == "lan")
statusmenu += "<b><#3161#> "+wans_lanport+" -</b><br>";
else if( wans_dualwan_array[0] == "usb")
statusmenu += "<b><#508#> -</b><br>";
}
if((first_link_status == "2" && first_link_auxstatus == "0") || (first_link_status == "2" && first_link_auxstatus == "2"))
statusmenu += "<span class='StatusClickHint' onclick='suspendconn(0, 0);' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'><#1892#></span>";
else{
statusmenu += "<span class='StatusClickHint' onclick='goToWAN(0);' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'>";
if(usb_index == 0){
if(gobi_support)
statusmenu += "<#2960#></span>";
else
statusmenu += "<#2408#></span>";
}
else
statusmenu += "<#3996#></span>";
}
if(gobi_support){
if( wans_dualwan_array[1] == "wan")
statusmenu += "<div class='StatusHint'><br><#2050#>:</div>";
else if( wans_dualwan_array[1] == "lan")
statusmenu += "<div class='StatusHint'><br>"+eLAN_str+" (<#3161#> "+wans_lanport+"):</div>";
else if( wans_dualwan_array[1] == "usb")
statusmenu += "<div class='StatusHint'><br><#2977#>:</div>";
}
else{
statusmenu += "<div class='StatusHint'><br><#2022#>:</div>";
if( wans_dualwan_array[1] == "wan")
statusmenu += "<b><#2050#> -</b><br>";
else if( wans_dualwan_array[1] == "lan")
statusmenu += "<b><#3161#> "+wans_lanport+" -</b><br>";
else if( wans_dualwan_array[1] == "usb")
statusmenu += "<b><#508#> -</b><br>";
}
if((secondary_link_status == "2" && secondary_link_auxstatus == "0") || (secondary_link_status == "2" && secondary_link_auxstatus == "2"))
statusmenu += "<span class='StatusClickHint' onclick='suspendconn(1, 0);' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'><#1892#></span>";
else{
statusmenu += "<span class='StatusClickHint' onclick='goToWAN(1);' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'>";
if(usb_index == 1){
if(gobi_support)
statusmenu += "<#2960#></span>";
else
statusmenu += "<#2408#></span>";
}
else
statusmenu += "<#3996#></span>";
}
}
}
else if(sw_mode == 2){
statusmenu = "<span class='StatusClickHint' onclick='top.location.href=\"/QIS_wizard.htm?flag=sitesurvey_rep\";' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'><#114#></span>";
}
else if(sw_mode == 4){
statusmenu = "<span class='StatusClickHint' onclick='top.location.href=\"/QIS_wizard.htm?flag=sitesurvey_mb\";' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'><#114#></span>";
}
_caption = "Internet Status";
}
else if(hint_show_id == 2){
statusmenu = "";
require(['/require/modules/diskList.js'], function(diskList){
var usbDevicesList = diskList.list();
for(var i=0; i<usbDevicesList.length; i++){
if(usbDevicesList[i].mountNumber > 0){
statusmenu += "<div style='margin-top:2px;' class='StatusClickHint' onclick='remove_disk("+ usbDevicesList[i].node +");' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'>";
statusmenu += "<#2026#> <span style='font-weight:normal'>"+ usbDevicesList[i].deviceName +"</span></div>";
}
}
if(statusmenu == "")
statusmenu = "<span class='StatusHint'><#1893#></span>";
else if(statusmenu.howMany("remove_disk") > 1)
statusmenu += "<div style='margin-top:2px;' class='StatusClickHint' onclick='remove_all_disk();' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'>Eject all USB disks</div>";
_caption = "USB storage";
return overlib(statusmenu, OFFSETX, -160, LEFT, STICKY, CAPTION, " ", CLOSETITLE, '');
});
}
else if(hint_show_id == 1){
if(hadPlugged("printer"))
statusmenu = "<span class='StatusClickHint' onclick='enableMonomode();' onmouseout='this.className=\"StatusClickHint\"' onmouseover='this.className=\"StatusClickHint_mouseover\"'>Enable Monopoly mode</span>";
else
statusmenu = "<span class='StatusHint'><#3064#></span>";
_caption = "Printer";
}
return overlib(statusmenu, OFFSETX, -160, LEFT, STICKY, CAPTION, " ", CLOSETITLE, '');
}
else if(hint_array_id == 28){ //wan aggregation
statusmenu = "<div>";
statusmenu += "<#4052#>";
statusmenu += "<ol>";
statusmenu += "<li><#4053#></li>".replace("LAN 4", wanAggr_p2_name(orig_wanports_bond));
statusmenu += "<li><#4054#></li>";
statusmenu += "<li><#4055#></li>";
statusmenu += "<li><#4056#></li>";
statusmenu += "</ol>";
statusmenu += "<#4057#>";
statusmenu += "</div>";
return overlib(statusmenu, OFFSETX, -160, LEFT, DELAY, 400, WIDTH, 300, STICKY, CAPTION, " ");
}
var tag_name= document.getElementsByTagName('a');
for (var i=0;i<tag_name.length;i++)
tag_name[i].onmouseout=nd;
if(helpcontent == [] || helpcontent == "" || hint_array_id > helpcontent.length)
return overlib('<#308#>', HAUTO, VAUTO);
else if(hint_array_id == 0 && hint_show_id > 21 && hint_show_id < 24)
return overlib(helpcontent[hint_array_id][hint_show_id], FIXX, 270, FIXY, 30);
else{
if(hint_show_id > helpcontent[hint_array_id].length)
return overlib('<#308#>', HAUTO, VAUTO);
else
return overlib(helpcontent[hint_array_id][hint_show_id], HAUTO, VAUTO);
}
}
var olLoaded = 0;var pmStart = 10000000; var pmUpper = 10001000; var pmCount = pmStart+1; var pmt=''; var pms = new Array(); var olInfo = new Info('4.21', 1);
var FREPLACE = 0; var FBEFORE = 1; var FAFTER = 2; var FALTERNATE = 3; var FCHAIN=4;
var olHideForm=0; // parameter for hiding SELECT and ActiveX elements in IE5.5+
var olHautoFlag = 0; // flags for over-riding VAUTO and HAUTO if corresponding
var olVautoFlag = 0; // positioning commands are used on the command line
var hookPts = new Array(), postParse = new Array(), cmdLine = new Array(), runTime = new Array();
registerCommands('donothing,inarray,caparray,sticky,background,noclose,caption,left,right,center,offsetx,offsety,fgcolor,bgcolor,textcolor,capcolor,closecolor,width,border,cellpad,status,autostatus,autostatuscap,height,closetext,snapx,snapy,fixx,fixy,relx,rely,fgbackground,bgbackground,padx,pady,fullhtml,above,below,capicon,textfont,captionfont,closefont,textsize,captionsize,closesize,timeout,function,delay,hauto,vauto,closeclick,wrap,followmouse,mouseoff,closetitle,cssoff,compatmode,cssclass,fgclass,bgclass,textfontclass,captionfontclass,closefontclass');
if (typeof ol_fgcolor=='undefined') var ol_fgcolor="#EEEEEE";
if (typeof ol_bgcolor=='undefined') var ol_bgcolor="#CCC";
if (typeof ol_textcolor=='undefined') var ol_textcolor="#000000";
if (typeof ol_capcolor=='undefined') var ol_capcolor="#777";
if (typeof ol_closecolor=='undefined') var ol_closecolor="#000000";
if (typeof ol_textfont=='undefined') var ol_textfont="Verdana,Arial,Helvetica";
if (typeof ol_captionfont=='undefined') var ol_captionfont="Verdana,Arial,Helvetica";
if (typeof ol_closefont=='undefined') var ol_closefont="Verdana,Arial,Helvetica";
if (typeof ol_textsize=='undefined') var ol_textsize="2";
if (typeof ol_captionsize=='undefined') var ol_captionsize="1";
if (typeof ol_closesize=='undefined') var ol_closesize="2";
if (typeof ol_width=='undefined') var ol_width="200";
if (typeof ol_border=='undefined') var ol_border="1";
if (typeof ol_cellpad=='undefined') var ol_cellpad=6;
if (typeof ol_offsetx=='undefined') var ol_offsetx=10;
if (typeof ol_offsety=='undefined') var ol_offsety=10;
if (typeof ol_text=='undefined') var ol_text='<#1073#>';
if (typeof ol_cap=='undefined') var ol_cap="";
if (typeof ol_sticky=='undefined') var ol_sticky=0;
if (typeof ol_background=='undefined') var ol_background="";
if (typeof ol_close=='undefined') var ol_close="&times;&nbsp;";
if (typeof ol_hpos=='undefined') var ol_hpos=RIGHT;
if (typeof ol_status=='undefined') var ol_status="";
if (typeof ol_autostatus=='undefined') var ol_autostatus=0;
if (typeof ol_height=='undefined') var ol_height=-1;
if (typeof ol_snapx=='undefined') var ol_snapx=0;
if (typeof ol_snapy=='undefined') var ol_snapy=0;
if (typeof ol_fixx=='undefined') var ol_fixx=-1;
if (typeof ol_fixy=='undefined') var ol_fixy=-1;
if (typeof ol_relx=='undefined') var ol_relx=null;
if (typeof ol_rely=='undefined') var ol_rely=null;
if (typeof ol_fgbackground=='undefined') var ol_fgbackground="";
if (typeof ol_bgbackground=='undefined') var ol_bgbackground="";
if (typeof ol_padxl=='undefined') var ol_padxl=1;
if (typeof ol_padxr=='undefined') var ol_padxr=1;
if (typeof ol_padyt=='undefined') var ol_padyt=1;
if (typeof ol_padyb=='undefined') var ol_padyb=1;
if (typeof ol_fullhtml=='undefined') var ol_fullhtml=0;
if (typeof ol_vpos=='undefined') var ol_vpos=BELOW;
if (typeof ol_aboveheight=='undefined') var ol_aboveheight=0;
if (typeof ol_capicon=='undefined') var ol_capicon="";
if (typeof ol_frame=='undefined') var ol_frame=self;
if (typeof ol_timeout=='undefined') var ol_timeout=0;
if (typeof ol_function=='undefined') var ol_function=null;
if (typeof ol_delay=='undefined') var ol_delay=0;
if (typeof ol_hauto=='undefined') var ol_hauto=0;
if (typeof ol_vauto=='undefined') var ol_vauto=0;
if (typeof ol_closeclick=='undefined') var ol_closeclick=0;
if (typeof ol_wrap=='undefined') var ol_wrap=0;
if (typeof ol_followmouse=='undefined') var ol_followmouse=1;
if (typeof ol_mouseoff=='undefined') var ol_mouseoff=0;
if (typeof ol_closetitle=='undefined') var ol_closetitle='Close';
if (typeof ol_compatmode=='undefined') var ol_compatmode=0;
if (typeof ol_css=='undefined') var ol_css=CSSOFF;
if (typeof ol_fgclass=='undefined') var ol_fgclass="";
if (typeof ol_bgclass=='undefined') var ol_bgclass="";
if (typeof ol_textfontclass=='undefined') var ol_textfontclass="";
if (typeof ol_captionfontclass=='undefined') var ol_captionfontclass="";
if (typeof ol_closefontclass=='undefined') var ol_closefontclass="";
if (typeof ol_texts=='undefined') var ol_texts = new Array("Text 0", "Text 1");
if (typeof ol_caps=='undefined') var ol_caps = new Array("Caption 0", "Caption 1");
var o3_text="";
var o3_cap="";
var o3_sticky=0;
var o3_background="";
var o3_close="Close";
var o3_hpos=RIGHT;
var o3_offsetx=2;
var o3_offsety=2;
var o3_fgcolor="";
var o3_bgcolor="";
var o3_textcolor="";
var o3_capcolor="";
var o3_closecolor="";
var o3_width=100;
var o3_border=1;
var o3_cellpad=2;
var o3_status="";
var o3_autostatus=0;
var o3_height=-1;
var o3_snapx=0;
var o3_snapy=0;
var o3_fixx=-1;
var o3_fixy=-1;
var o3_relx=null;
var o3_rely=null;
var o3_fgbackground="";
var o3_bgbackground="";
var o3_padxl=0;
var o3_padxr=0;
var o3_padyt=0;
var o3_padyb=0;
var o3_fullhtml=0;
var o3_vpos=BELOW;
var o3_aboveheight=0;
var o3_capicon="";
var o3_textfont="Verdana,Arial,Helvetica";
var o3_captionfont="Verdana,Arial,Helvetica";
var o3_closefont="Verdana,Arial,Helvetica";
var o3_textsize="1";
var o3_captionsize="1";
var o3_closesize="1";
var o3_frame=self;
var o3_timeout=0;
var o3_timerid=0;
var o3_allowmove=0;
var o3_function=null;
var o3_delay=0;
var o3_delayid=0;
var o3_hauto=0;
var o3_vauto=0;
var o3_closeclick=0;
var o3_wrap=0;
var o3_followmouse=1;
var o3_mouseoff=0;
var o3_closetitle='';
var o3_compatmode=0;
var o3_css=CSSOFF;
var o3_fgclass="";
var o3_bgclass="";
var o3_textfontclass="";
var o3_captionfontclass="";
var o3_closefontclass="";
var o3_x = 0;
var o3_y = 0;
var o3_showingsticky = 0;
var o3_removecounter = 0;
var over = null;
var fnRef, hoveringSwitch = false;
var olHideDelay;
var isMac = (navigator.userAgent.indexOf("Mac") != -1);
var olOp = (navigator.userAgent.toLowerCase().indexOf('opera') > -1 && document.createTextNode); // Opera 7
var olNs4 = (navigator.appName=='Netscape' && parseInt(navigator.appVersion) == 4);
var olNs6 = (document.getElementById) ? true : false;
var olKq = (olNs6 && /konqueror/i.test(navigator.userAgent));
var olIe4 = (document.all) ? true : false;
var olIe5 = false;
var olIe55 = false; // Added additional variable to identify IE5.5+
var docRoot = 'document.body';
if (olNs4) {
var oW = window.innerWidth;
var oH = window.innerHeight;
window.onresize = function() { if (oW != window.innerWidth || oH != window.innerHeight) location.reload(); }
}
if (olIe4) {
var agent = navigator.userAgent;
if (/MSIE/.test(agent)) {
var versNum = parseFloat(agent.match(/MSIE[ ](\d+\.\d+)\.*/i)[1]);
if (versNum >= 5){
olIe5=true;
olIe55=(versNum>=5.5&&!olOp) ? true : false;
if (olNs6) olNs6=false;
}
}
if (olNs6) olIe4 = false;
}
if (document.compatMode && document.compatMode == 'CSS1Compat') {
docRoot= ((olIe4 && !olOp) ? 'document.documentElement' : docRoot);
}
if(window.addEventListener) window.addEventListener("load",OLonLoad_handler,false);
else if (window.attachEvent) window.attachEvent("onload",OLonLoad_handler);
var capExtent;
function overlib() {
if(typeof overlib.isOut != "undefined")
overlib.isOut = false;
if (!olLoaded || isExclusive(overlib.arguments)) return true;
if (olCheckMouseCapture) olMouseCapture();
if (over) {
over = (typeof over.id != 'string') ? o3_frame.document.all['overDiv'] : over;
cClick();
}
olHideDelay=0;
o3_text=ol_text;
o3_cap=ol_cap;
o3_sticky=ol_sticky;
o3_background=ol_background;
o3_close=ol_close;
o3_hpos=ol_hpos;
o3_offsetx=ol_offsetx;
o3_offsety=ol_offsety;
o3_fgcolor=ol_fgcolor;
o3_bgcolor=ol_bgcolor;
o3_textcolor=ol_textcolor;
o3_capcolor=ol_capcolor;
o3_closecolor=ol_closecolor;
o3_width=ol_width;
o3_border=ol_border;
o3_cellpad=ol_cellpad;
o3_status=ol_status;
o3_autostatus=ol_autostatus;
o3_height=ol_height;
o3_snapx=ol_snapx;
o3_snapy=ol_snapy;
o3_fixx=ol_fixx;
o3_fixy=ol_fixy;
o3_relx=ol_relx;
o3_rely=ol_rely;
o3_fgbackground=ol_fgbackground;
o3_bgbackground=ol_bgbackground;
o3_padxl=ol_padxl;
o3_padxr=ol_padxr;
o3_padyt=ol_padyt;
o3_padyb=ol_padyb;
o3_fullhtml=ol_fullhtml;
o3_vpos=ol_vpos;
o3_aboveheight=ol_aboveheight;
o3_capicon=ol_capicon;
o3_textfont=ol_textfont;
o3_captionfont=ol_captionfont;
o3_closefont=ol_closefont;
o3_textsize=ol_textsize;
o3_captionsize=ol_captionsize;
o3_closesize=ol_closesize;
o3_timeout=ol_timeout;
o3_function=ol_function;
o3_delay=ol_delay;
o3_hauto=ol_hauto;
o3_vauto=ol_vauto;
o3_closeclick=ol_closeclick;
o3_wrap=ol_wrap;
o3_followmouse=ol_followmouse;
o3_mouseoff=ol_mouseoff;
o3_closetitle=ol_closetitle;
o3_css=ol_css;
o3_compatmode=ol_compatmode;
o3_fgclass=ol_fgclass;
o3_bgclass=ol_bgclass;
o3_textfontclass=ol_textfontclass;
o3_captionfontclass=ol_captionfontclass;
o3_closefontclass=ol_closefontclass;
setRunTimeVariables();
fnRef = '';
o3_frame = ol_frame;
if(!(over=createDivContainer())) return false;
parseTokens('o3_', overlib.arguments);
if (!postParseChecks()) return false;
if (o3_delay == 0) {
return runHook("olMain", FREPLACE);
} else {
o3_delayid = setTimeout("runHook('olMain', FREPLACE)", o3_delay);
return false;
}
}
function nd(time) {
if(typeof overlib.isOut != "undefined")
overlib.isOut = true;
if (olLoaded && !isExclusive()) {
hideDelay(time); // delay popup close if time specified
if (o3_removecounter >= 1) { o3_showingsticky = 0 };
if (o3_showingsticky == 0) {
o3_allowmove = 0;
if (over != null && o3_timerid == 0) runHook("hideObject", FREPLACE, over);
} else {
o3_removecounter++;
}
}
return true;
}
function cClick() {
if (olLoaded) {
runHook("hideObject", FREPLACE, over);
o3_showingsticky = 0;
}
return false;
}
function overlib_pagedefaults() {
parseTokens('ol_', overlib_pagedefaults.arguments);
}
function olMain() {
var layerhtml, styleType;
runHook("olMain", FBEFORE);
if (o3_background!="" || o3_fullhtml) {
layerhtml = runHook('ol_content_background', FALTERNATE, o3_css, o3_text, o3_background, o3_fullhtml);
} else {
styleType = (pms[o3_css-1-pmStart] == "cssoff" || pms[o3_css-1-pmStart] == "cssclass");
if (o3_fgbackground != "") o3_fgbackground = "background=\""+o3_fgbackground+"\"";
if (o3_bgbackground != "") o3_bgbackground = (styleType ? "background=\""+o3_bgbackground+"\"" : o3_bgbackground);
if (o3_fgcolor != "") o3_fgcolor = (styleType ? "bgcolor=\""+o3_fgcolor+"\"" : o3_fgcolor);
if (o3_bgcolor != "") o3_bgcolor = (styleType ? "bgcolor=\""+o3_bgcolor+"\"" : o3_bgcolor);
if (o3_height > 0) o3_height = (styleType ? "height=\""+o3_height+"\"" : o3_height);
else o3_height = "";
if (o3_cap=="") {
layerhtml = runHook('ol_content_simple', FALTERNATE, o3_css, o3_text);
} else {
if (o3_sticky) {
layerhtml = runHook('ol_content_caption', FALTERNATE, o3_css, o3_text, o3_cap, o3_close);
} else {
layerhtml = runHook('ol_content_caption', FALTERNATE, o3_css, o3_text, o3_cap, "");
}
}
}
if (o3_sticky) {
if (o3_timerid > 0) {
clearTimeout(o3_timerid);
o3_timerid = 0;
}
o3_showingsticky = 1;
o3_removecounter = 0;
}
if (!runHook("createPopup", FREPLACE, layerhtml)) return false;
if (o3_autostatus > 0) {
o3_status = o3_text;
if (o3_autostatus > 1) o3_status = o3_cap;
}
o3_allowmove = 0;
if (o3_timeout > 0) {
if (o3_timerid > 0) clearTimeout(o3_timerid);
o3_timerid = setTimeout("cClick()", o3_timeout);
}
runHook("disp", FREPLACE, o3_status);
runHook("olMain", FAFTER);
return (olOp && event && event.type == 'mouseover' && !o3_status) ? '' : (o3_status != '');
}
function ol_content_simple(text) {
var cpIsMultiple = /,/.test(o3_cellpad);
var txt = '<table id="overDiv_table1" width="'+o3_width+ '" border="0" cellpadding="'+o3_border+'" cellspacing="0" '+(o3_bgclass ? 'class="'+o3_bgclass+'"' : o3_bgcolor+' '+o3_height)+'><tr><td><table id="overDiv_table2" width="100%" border="0" '+((olNs4||!cpIsMultiple) ? 'cellpadding="'+o3_cellpad+'" ' : '')+'cellspacing="0" '+(o3_fgclass ? 'class="'+o3_fgclass+'"' : o3_fgcolor+' '+o3_fgbackground+' '+o3_height)+'><tr><td valign="TOP"'+(o3_textfontclass ? ' class="'+o3_textfontclass+'">' : ((!olNs4&&cpIsMultiple) ? ' style="'+setCellPadStr(o3_cellpad)+'">' : '>'))+(o3_textfontclass ? '' : wrapStr(0,o3_textsize,'text'))+text+(o3_textfontclass ? '' : wrapStr(1,o3_textsize))+'</td></tr></table></td></tr></table>';
set_background("");
return txt;
}
function ol_content_caption(text,title,close) {
var nameId, txt, cpIsMultiple = /,/.test(o3_cellpad);
var closing, closeevent;
closing = "";
closeevent = "onclick";
if (o3_closeclick == 1) closeevent = (o3_closetitle ? "title='" + o3_closetitle +"'" : "") + " onclick";
if (o3_capicon != "") {
nameId = ' hspace = \"5\"'+' align = \"middle\" alt = \"\"';
if (typeof o3_dragimg != 'undefined' && o3_dragimg) nameId =' hspace=\"5\"'+' name=\"'+o3_dragimg+'\" id=\"'+o3_dragimg+'\" align=\"middle\" alt=\"Drag Enabled\" title=\"Drag Enabled\"';
o3_capicon = '<img src=\"'+o3_capicon+'\"'+nameId+' />';
}
if (close != "")
closing = '<td '+(!o3_compatmode && o3_closefontclass ? 'class="'+o3_closefontclass : 'align="RIGHT')+'"><a href="javascript:return '+fnRef+'cClick();"'+((o3_compatmode && o3_closefontclass) ? ' class="' + o3_closefontclass + '" ' : ' ')+closeevent+'="return '+fnRef+'cClick();"><img width="18px" height="18px" src="/images/button-close.png" onmouseover="this.src=\'/images/button-close2.png\'" onmouseout="this.src=\'/images/button-close.png\'" border="0"></a></td>';
txt = '<table id="overDiv_table3" width="'+o3_width+ '" border="0" cellpadding="0" cellspacing="0" '+(o3_bgclass ? 'class="'+o3_bgclass+'"' : o3_bgcolor+' '+o3_bgbackground+' '+o3_height)+'><tr><td><table id="overDiv_table4" bgColor="#CCCCCC" width="100%" border="0" cellpadding="0" cellspacing="0"><tr><td'+(o3_captionfontclass ? ' class="'+o3_captionfontclass+'">' : '>')+(o3_captionfontclass ? '' : '<b>'+wrapStr(0,o3_captionsize,'caption'))+o3_capicon+title+(o3_captionfontclass ? '' : wrapStr(1,o3_captionsize)+'</b>')+'</td>'+closing+'</tr></table><table id="overDiv_table5" width="100%" border="0" '+((olNs4||!cpIsMultiple) ? 'cellpadding="5" ' : '')+'cellspacing="0" '+(o3_fgclass ? 'class="'+o3_fgclass+'"' : o3_fgcolor+' '+o3_fgbackground+' '+o3_height)+'><tr><td valign="TOP"'+(o3_textfontclass ? ' class="'+o3_textfontclass+'">' :((!olNs4&&cpIsMultiple) ? ' style="'+setCellPadStr(o3_cellpad)+'">' : '>'))+(o3_textfontclass ? '' : wrapStr(0,o3_textsize,'text'))+text+(o3_textfontclass ? '' : wrapStr(1,o3_textsize)) + '</td></tr></table></td></tr></table>';
set_background("");
return txt;
}
function ol_content_background(text,picture,hasfullhtml) {
if (hasfullhtml) {
txt=text;
} else {
txt='<table id="overDiv_table5" width="'+o3_width+'" border="0" cellpadding="0" cellspacing="0" height="'+o3_height+'"><tr><td colspan="3" height="'+o3_padyt+'"></td></tr><tr><td width="'+o3_padxl+'"></td><td valign="TOP" width="'+(o3_width-o3_padxl-o3_padxr)+(o3_textfontclass ? '" class="'+o3_textfontclass : '')+'">'+(o3_textfontclass ? '' : wrapStr(0,o3_textsize,'text'))+text+(o3_textfontclass ? '' : wrapStr(1,o3_textsize))+'</td><td width="'+o3_padxr+'"></td></tr><tr><td colspan="3" height="'+o3_padyb+'"></td></tr></table>';
}
set_background(picture);
return txt;
}
function set_background(pic){
if (pic == "") {
if (olNs4) {
over.background.src = null;
} else if (over.style) {
over.style.backgroundImage = "none";
}
} else {
if (olNs4) {
over.background.src = pic;
} else if (over.style) {
over.style.width=o3_width + 'px';
over.style.backgroundImage = "url("+pic+")";
}
}
}
var olShowId=-1;
function disp(statustext) {
runHook("disp", FBEFORE);
if (o3_allowmove == 0) {
runHook("placeLayer", FREPLACE);
(olNs6&&olShowId<0) ? olShowId=setTimeout("runHook('showObject', FREPLACE, over)", 1) : runHook("showObject", FREPLACE, over);
o3_allowmove = (o3_sticky || o3_followmouse==0) ? 0 : 1;
}
runHook("disp", FAFTER);
if (statustext != "") self.status = statustext;
}
function createPopup(lyrContent){
runHook("createPopup", FBEFORE);
if (o3_wrap) {
var wd,ww,theObj = (olNs4 ? over : over.style);
theObj.top = theObj.left = ((olIe4&&!olOp) ? 0 : -10000) + (!olNs4 ? 'px' : 0);
layerWrite(lyrContent);
wd = (olNs4 ? over.clip.width : over.offsetWidth);
if (wd > (ww=windowWidth())) {
lyrContent=lyrContent.replace(/\&nbsp;/g, ' ');
o3_width=ww;
o3_wrap=0;
}
}
layerWrite(lyrContent);
if (o3_wrap) o3_width=(olNs4 ? over.clip.width : over.offsetWidth);
runHook("createPopup", FAFTER, lyrContent);
return true;
}
function placeLayer() {
var placeX, placeY, widthFix = 0;
if (o3_frame.innerWidth) widthFix=18;
iwidth = windowWidth();
winoffset=(olIe4) ? eval('o3_frame.'+docRoot+'.scrollLeft') : o3_frame.pageXOffset;
placeX = runHook('horizontalPlacement',FCHAIN,iwidth,winoffset,widthFix);
if (o3_frame.innerHeight) {
iheight=o3_frame.innerHeight;
} else if (eval('o3_frame.'+docRoot)&&eval("typeof o3_frame."+docRoot+".clientHeight=='number'")&&eval('o3_frame.'+docRoot+'.clientHeight')) {
iheight=eval('o3_frame.'+docRoot+'.clientHeight');
}
scrolloffset=(olIe4) ? eval('o3_frame.'+docRoot+'.scrollTop') : o3_frame.pageYOffset;
placeY = runHook('verticalPlacement',FCHAIN,iheight,scrolloffset);
repositionTo(over, placeX, placeY);
}
function olMouseMove(e) {
var e = (e) ? e : event;
if (e.pageX) {
o3_x = e.pageX;
o3_y = e.pageY;
} else if (e.clientX) {
o3_x = eval('e.clientX+o3_frame.'+docRoot+'.scrollLeft');
o3_y = eval('e.clientY+o3_frame.'+docRoot+'.scrollTop');
}
if (o3_allowmove == 1) runHook("placeLayer", FREPLACE);
if (hoveringSwitch && !olNs4 && runHook("cursorOff", FREPLACE)) {
(olHideDelay ? hideDelay(olHideDelay) : cClick());
hoveringSwitch = !hoveringSwitch;
}
}
function no_overlib() { return ver3fix; }
function olMouseCapture() {
capExtent = document;
var fN, str = '', l, k, f, wMv, sS, mseHandler = olMouseMove;
var re = /function[ ]*(\w*)\(/;
wMv = (!olIe4 && window.onmousemove);
if (document.onmousemove || wMv) {
if (wMv) capExtent = window;
f = capExtent.onmousemove.toString();
fN = f.match(re);
if (fN == null) {
str = f+'(e); ';
} else if (fN[1] == 'anonymous' || fN[1] == 'olMouseMove' || (wMv && fN[1] == 'onmousemove')) {
if (!olOp && wMv) {
l = f.indexOf('{')+1;
k = f.lastIndexOf('}');
sS = f.substring(l,k);
if ((l = sS.indexOf('(')) != -1) {
sS = sS.substring(0,l).replace(/^\s+/,'').replace(/\s+$/,'');
if (eval("typeof " + sS + " == 'undefined'")) window.onmousemove = null;
else str = sS + '(e);';
}
}
if (!str) {
olCheckMouseCapture = false;
return;
}
} else {
if (fN[1]) str = fN[1]+'(e); ';
else {
l = f.indexOf('{')+1;
k = f.lastIndexOf('}');
str = f.substring(l,k) + '\n';
}
}
str += 'olMouseMove(e); ';
mseHandler = new Function('e', str);
}
capExtent.onmousemove = mseHandler;
if (olNs4) capExtent.captureEvents(Event.MOUSEMOVE);
}
function parseTokens(pf, ar) {
var v, i, mode=-1, par = (pf != 'ol_');
var fnMark = (par && !ar.length ? 1 : 0);
for (i = 0; i < ar.length; i++) {
if (mode < 0) {
if (typeof ar[i] == 'number' && ar[i] > pmStart && ar[i] < pmUpper) {
fnMark = (par ? 1 : 0);
i--; // backup one so that the next block can parse it
} else {
switch(pf) {
case 'ol_':
ol_text = ar[i].toString();
break;
default:
o3_text=ar[i].toString();
}
}
mode = 0;
} else {
if (ar[i] >= pmCount || ar[i]==DONOTHING) { continue; }
if (ar[i]==INARRAY) { fnMark = 0; eval(pf+'text=ol_texts['+ar[++i]+'].toString()'); continue; }
if (ar[i]==CAPARRAY) { eval(pf+'cap=ol_caps['+ar[++i]+'].toString()'); continue; }
if (ar[i]==STICKY) { if (pf!='ol_') eval(pf+'sticky=1'); continue; }
if (ar[i]==BACKGROUND) { eval(pf+'background="'+ar[++i]+'"'); continue; }
if (ar[i]==NOCLOSE) { if (pf!='ol_') opt_NOCLOSE(); continue; }
if (ar[i]==CAPTION) { eval(pf+"cap='"+escSglQuote(ar[++i])+"'"); continue; }
if (ar[i]==CENTER || ar[i]==LEFT || ar[i]==RIGHT) { eval(pf+'hpos='+ar[i]); if(pf!='ol_') olHautoFlag=1; continue; }
if (ar[i]==OFFSETX) { eval(pf+'offsetx='+ar[++i]); continue; }
if (ar[i]==OFFSETY) { eval(pf+'offsety='+ar[++i]); continue; }
if (ar[i]==FGCOLOR) { eval(pf+'fgcolor="'+ar[++i]+'"'); continue; }
if (ar[i]==BGCOLOR) { eval(pf+'bgcolor="'+ar[++i]+'"'); continue; }
if (ar[i]==TEXTCOLOR) { eval(pf+'textcolor="'+ar[++i]+'"'); continue; }
if (ar[i]==CAPCOLOR) { eval(pf+'capcolor="'+ar[++i]+'"'); continue; }
if (ar[i]==CLOSECOLOR) { eval(pf+'closecolor="'+ar[++i]+'"'); continue; }
if (ar[i]==WIDTH) { eval(pf+'width='+ar[++i]); continue; }
if (ar[i]==BORDER) { eval(pf+'border='+ar[++i]); continue; }
if (ar[i]==CELLPAD) { i=opt_MULTIPLEARGS(++i,ar,(pf+'cellpad')); continue; }
if (ar[i]==STATUS) { eval(pf+"status='"+escSglQuote(ar[++i])+"'"); continue; }
if (ar[i]==AUTOSTATUS) { eval(pf +'autostatus=('+pf+'autostatus == 1) ? 0 : 1'); continue; }
if (ar[i]==AUTOSTATUSCAP) { eval(pf +'autostatus=('+pf+'autostatus == 2) ? 0 : 2'); continue; }
if (ar[i]==HEIGHT) { eval(pf+'height='+pf+'aboveheight='+ar[++i]); continue; } // Same param again.
if (ar[i]==CLOSETEXT) { eval(pf+"close='"+escSglQuote(ar[++i])+"'"); continue; }
if (ar[i]==SNAPX) { eval(pf+'snapx='+ar[++i]); continue; }
if (ar[i]==SNAPY) { eval(pf+'snapy='+ar[++i]); continue; }
if (ar[i]==FIXX) { eval(pf+'fixx='+ar[++i]); continue; }
if (ar[i]==FIXY) { eval(pf+'fixy='+ar[++i]); continue; }
if (ar[i]==RELX) { eval(pf+'relx='+ar[++i]); continue; }
if (ar[i]==RELY) { eval(pf+'rely='+ar[++i]); continue; }
if (ar[i]==FGBACKGROUND) { eval(pf+'fgbackground="'+ar[++i]+'"'); continue; }
if (ar[i]==BGBACKGROUND) { eval(pf+'bgbackground="'+ar[++i]+'"'); continue; }
if (ar[i]==PADX) { eval(pf+'padxl='+ar[++i]); eval(pf+'padxr='+ar[++i]); continue; }
if (ar[i]==PADY) { eval(pf+'padyt='+ar[++i]); eval(pf+'padyb='+ar[++i]); continue; }
if (ar[i]==FULLHTML) { if (pf!='ol_') eval(pf+'fullhtml=1'); continue; }
if (ar[i]==BELOW || ar[i]==ABOVE) { eval(pf+'vpos='+ar[i]); if (pf!='ol_') olVautoFlag=1; continue; }
if (ar[i]==CAPICON) { eval(pf+'capicon="'+ar[++i]+'"'); continue; }
if (ar[i]==TEXTFONT) { eval(pf+"textfont='"+escSglQuote(ar[++i])+"'"); continue; }
if (ar[i]==CAPTIONFONT) { eval(pf+"captionfont='"+escSglQuote(ar[++i])+"'"); continue; }
if (ar[i]==CLOSEFONT) { eval(pf+"closefont='"+escSglQuote(ar[++i])+"'"); continue; }
if (ar[i]==TEXTSIZE) { eval(pf+'textsize="'+ar[++i]+'"'); continue; }
if (ar[i]==CAPTIONSIZE) { eval(pf+'captionsize="'+ar[++i]+'"'); continue; }
if (ar[i]==CLOSESIZE) { eval(pf+'closesize="'+ar[++i]+'"'); continue; }
if (ar[i]==TIMEOUT) { eval(pf+'timeout='+ar[++i]); continue; }
if (ar[i]==FUNCTION) { if (pf=='ol_') { if (typeof ar[i+1]!='number') { v=ar[++i]; ol_function=(typeof v=='function' ? v : null); }} else {fnMark = 0; v = null; if (typeof ar[i+1]!='number') v = ar[++i]; opt_FUNCTION(v); } continue; }
if (ar[i]==DELAY) { eval(pf+'delay='+ar[++i]); continue; }
if (ar[i]==HAUTO) { eval(pf+'hauto=('+pf+'hauto == 0) ? 1 : 0'); continue; }
if (ar[i]==VAUTO) { eval(pf+'vauto=('+pf+'vauto == 0) ? 1 : 0'); continue; }
if (ar[i]==CLOSECLICK) { eval(pf +'closeclick=('+pf+'closeclick == 0) ? 1 : 0'); continue; }
if (ar[i]==WRAP) { eval(pf +'wrap=('+pf+'wrap == 0) ? 1 : 0'); continue; }
if (ar[i]==FOLLOWMOUSE) { eval(pf +'followmouse=('+pf+'followmouse == 1) ? 0 : 1'); continue; }
if (ar[i]==MOUSEOFF) { eval(pf +'mouseoff=('+pf+'mouseoff==0) ? 1 : 0'); v=ar[i+1]; if (pf != 'ol_' && eval(pf+'mouseoff') && typeof v == 'number' && (v < pmStart || v > pmUpper)) olHideDelay=ar[++i]; continue; }
if (ar[i]==CLOSETITLE) { eval(pf+"closetitle='"+escSglQuote(ar[++i])+"'"); continue; }
if (ar[i]==CSSOFF||ar[i]==CSSCLASS) { eval(pf+'css='+ar[i]); continue; }
if (ar[i]==COMPATMODE) { eval(pf+'compatmode=('+pf+'compatmode==0) ? 1 : 0'); continue; }
if (ar[i]==FGCLASS) { eval(pf+'fgclass="'+ar[++i]+'"'); continue; }
if (ar[i]==BGCLASS) { eval(pf+'bgclass="'+ar[++i]+'"'); continue; }
if (ar[i]==TEXTFONTCLASS) { eval(pf+'textfontclass="'+ar[++i]+'"'); continue; }
if (ar[i]==CAPTIONFONTCLASS) { eval(pf+'captionfontclass="'+ar[++i]+'"'); continue; }
if (ar[i]==CLOSEFONTCLASS) { eval(pf+'closefontclass="'+ar[++i]+'"'); continue; }
i = parseCmdLine(pf, i, ar);
}
}
if (fnMark && o3_function) o3_text = o3_function();
if ((pf == 'o3_') && o3_wrap) {
o3_width = 0;
var tReg=/<.*\n*>/ig;
if (!tReg.test(o3_text)) o3_text = o3_text.replace(/[ ]+/g, '&nbsp;');
if (!tReg.test(o3_cap))o3_cap = o3_cap.replace(/[ ]+/g, '&nbsp;');
}
if ((pf == 'o3_') && o3_sticky) {
if (!o3_close && (o3_frame != ol_frame)) o3_close = ol_close;
if (o3_mouseoff && (o3_frame == ol_frame)) opt_NOCLOSE(' ');
}
}
function layerWrite(txt) {
txt += "\n";
if (olNs4) {
var lyr = o3_frame.document.layers['overDiv'].document
lyr.write(txt)
lyr.close()
} else if (typeof over.innerHTML != 'undefined') {
if (olIe5 && isMac) over.innerHTML = '';
over.innerHTML = txt;
} else {
range = o3_frame.document.createRange();
range.setStartAfter(over);
domfrag = range.createContextualFragment(txt);
while (over.hasChildNodes()) {
over.removeChild(over.lastChild);
}
over.appendChild(domfrag);
}
}
function showObject(obj) {
runHook("showObject", FBEFORE);
var theObj=(olNs4 ? obj : obj.style);
theObj.visibility = 'visible';
runHook("showObject", FAFTER);
}
function hideObject(obj) {
runHook("hideObject", FBEFORE);
var theObj=(olNs4 ? obj : obj.style);
if (olNs6 && olShowId>0) { clearTimeout(olShowId); olShowId=0; }
theObj.visibility = 'hidden';
theObj.top = theObj.left = ((olIe4&&!olOp) ? 0 : -10000) + (!olNs4 ? 'px' : 0);
if (o3_timerid > 0) clearTimeout(o3_timerid);
if (o3_delayid > 0) clearTimeout(o3_delayid);
o3_timerid = 0;
o3_delayid = 0;
self.status = "";
if (obj.onmouseout||obj.onmouseover) {
if (olNs4) obj.releaseEvents(Event.MOUSEOUT || Event.MOUSEOVER);
obj.onmouseout = obj.onmouseover = null;
}
runHook("hideObject", FAFTER);
}
function repositionTo(obj, xL, yL) {
var theObj=(olNs4 ? obj : obj.style);
theObj.left = xL + (!olNs4 ? 'px' : 0);
theObj.top = yL + (!olNs4 ? 'px' : 0);
}
function cursorOff() {
var left = parseInt(over.style.left);
var top = parseInt(over.style.top);
var right = left + (over.offsetWidth >= parseInt(o3_width) ? over.offsetWidth : parseInt(o3_width));
var bottom = top + (over.offsetHeight >= o3_aboveheight ? over.offsetHeight : o3_aboveheight);
if (o3_x < left || o3_x > right || o3_y < top || o3_y > bottom) return true;
return false;
}
function opt_FUNCTION(callme) {
o3_text = (callme ? (typeof callme=='string' ? (/.+\(.*\)/.test(callme) ? eval(callme) : callme) : callme()) : (o3_function ? o3_function() : 'No Function'));
return 0;
}
function opt_NOCLOSE(unused) {
if (!unused) o3_close = "";
if (olNs4) {
over.captureEvents(Event.MOUSEOUT || Event.MOUSEOVER);
over.onmouseover = function () { if (o3_timerid > 0) { clearTimeout(o3_timerid); o3_timerid = 0; } }
over.onmouseout = function (e) { if (olHideDelay) hideDelay(olHideDelay); else cClick(e); }
} else {
over.onmouseover = function () {hoveringSwitch = true; if (o3_timerid > 0) { clearTimeout(o3_timerid); o3_timerid =0; } }
}
return 0;
}
function opt_MULTIPLEARGS(i, args, parameter) {
var k=i, re, pV, str='';
for(k=i; k<args.length; k++) {
if(typeof args[k] == 'number' && args[k]>pmStart) break;
str += args[k] + ',';
}
if (str) str = str.substring(0,--str.length);
k--; // reduce by one so the for loop this is in works correctly
pV=(olNs4 && /cellpad/i.test(parameter)) ? str.split(',')[0] : str;
eval(parameter + '="' + pV + '"');
return k;
}
function nbspCleanup() {
if (o3_wrap) {
o3_text = o3_text.replace(/\&nbsp;/g, ' ');
o3_cap = o3_cap.replace(/\&nbsp;/g, ' ');
}
}
function escSglQuote(str) {
return str.toString().replace(/'/g,"\\'");
}
function OLonLoad_handler(e) {
var re = /\w+\(.*\)[;\s]+/g, olre = /overlib\(|nd\(|cClick\(/, fn, l, i;
if(!olLoaded) olLoaded=1;
if(window.removeEventListener && e.eventPhase == 3) window.removeEventListener("load",OLonLoad_handler,false);
else if(window.detachEvent) { // and for IE and Opera 4.x but execute calls to overlib, nd, or cClick()
window.detachEvent("onload",OLonLoad_handler);
var fN = document.body.getAttribute('onload');
if (fN) {
fN=fN.toString().match(re);
if (fN && fN.length) {
for (i=0; i<fN.length; i++) {
if (/anonymous/.test(fN[i])) continue;
while((l=fN[i].search(/\)[;\s]+/)) != -1) {
fn=fN[i].substring(0,l+1);
fN[i] = fN[i].substring(l+2);
if (olre.test(fn)) eval(fn);
}
}
}
}
}
}
function wrapStr(endWrap,fontSizeStr,whichString) {
var fontStr, fontColor, isClose=((whichString=='close') ? 1 : 0), hasDims=/[%\-a-z]+$/.test(fontSizeStr);
fontSizeStr = (olNs4) ? (!hasDims ? fontSizeStr : '1') : fontSizeStr;
if (endWrap) return (hasDims&&!olNs4) ? (isClose ? '</span>' : '</div>') : '</font>';
else {
fontStr='o3_'+whichString+'font';
fontColor='o3_'+((whichString=='caption')? 'cap' : whichString)+'color';
return (hasDims&&!olNs4) ? (isClose ? '<span style="font-family: '+quoteMultiNameFonts(eval(fontStr))+'; color: '+eval(fontColor)+'; font-size: '+fontSizeStr+';">' : '<div style="font-family: '+quoteMultiNameFonts(eval(fontStr))+'; color: '+eval(fontColor)+'; font-size: '+fontSizeStr+';">') : '<font face="'+eval(fontStr)+'" color="'+eval(fontColor)+'" size="'+(parseInt(fontSizeStr)>7 ? '7' : fontSizeStr)+'">';
}
}
function quoteMultiNameFonts(theFont) {
var v, pM=theFont.split(',');
for (var i=0; i<pM.length; i++) {
v=pM[i];
v=v.replace(/^\s+/,'').replace(/\s+$/,'');
if(/\s/.test(v) && !/['"]/.test(v)) {
v="\'"+v+"\'";
pM[i]=v;
}
}
return pM.join();
}
function isExclusive(args) {
return false;
}
function setCellPadStr(parameter) {
var Str='', j=0, ary = new Array(), top, bottom, left, right;
Str+='padding: ';
ary=parameter.replace(/\s+/g,'').split(',');
switch(ary.length) {
case 2:
top=bottom=ary[j];
left=right=ary[++j];
break;
case 3:
top=ary[j];
left=right=ary[++j];
bottom=ary[++j];
break;
case 4:
top=ary[j];
right=ary[++j];
bottom=ary[++j];
left=ary[++j];
break;
}
Str+= ((ary.length==1) ? ary[0] + 'px;' : top + 'px ' + right + 'px ' + bottom + 'px ' + left + 'px;');
return Str;
}
function hideDelay(time) {
if (time&&!o3_delay) {
if (o3_timerid > 0) clearTimeout(o3_timerid);
o3_timerid=setTimeout("cClick()",(o3_timeout=time));
}
}
function horizontalPlacement(browserWidth, horizontalScrollAmount, widthFix) {
var placeX, iwidth=browserWidth, winoffset=horizontalScrollAmount;
var parsedWidth = parseInt(o3_width);
if (o3_fixx > -1 || o3_relx != null) {
placeX=(o3_relx != null ? ( o3_relx < 0 ? winoffset +o3_relx+ iwidth - parsedWidth - widthFix : winoffset+o3_relx) : o3_fixx);
} else {
if (o3_hauto == 1) {
if ((o3_x - winoffset) > (iwidth / 2)) {
o3_hpos = LEFT;
} else {
o3_hpos = RIGHT;
}
}
if (o3_hpos == CENTER) { // Center
placeX = o3_x+o3_offsetx-(parsedWidth/2);
if (placeX < winoffset) placeX = winoffset;
}
if (o3_hpos == RIGHT) { // Right
placeX = o3_x+o3_offsetx;
if ((placeX+parsedWidth) > (winoffset+iwidth - widthFix)) {
placeX = iwidth+winoffset - parsedWidth - widthFix;
if (placeX < 0) placeX = 0;
}
}
if (o3_hpos == LEFT) { // Left
placeX = o3_x-o3_offsetx-parsedWidth-150;
if (placeX < winoffset) placeX = winoffset;
}
if (o3_snapx > 1) {
var snapping = placeX % o3_snapx;
if (o3_hpos == LEFT) {
placeX = placeX - (o3_snapx+snapping);
} else {
placeX = placeX+(o3_snapx - snapping);
}
if (placeX < winoffset) placeX = winoffset;
}
}
return placeX;
}
function verticalPlacement(browserHeight,verticalScrollAmount) {
var placeY, iheight=browserHeight, scrolloffset=verticalScrollAmount;
var parsedHeight=(o3_aboveheight ? parseInt(o3_aboveheight) : (olNs4 ? over.clip.height : over.offsetHeight));
if (o3_fixy > -1 || o3_rely != null) {
placeY=(o3_rely != null ? (o3_rely < 0 ? scrolloffset+o3_rely+iheight - parsedHeight : scrolloffset+o3_rely) : o3_fixy);
} else {
if (o3_vauto == 1) {
if ((o3_y - scrolloffset) > (iheight / 2) && o3_vpos == BELOW && (o3_y + parsedHeight + o3_offsety - (scrolloffset + iheight) > 0)) {
o3_vpos = ABOVE;
} else if (o3_vpos == ABOVE && (o3_y - (parsedHeight + o3_offsety) - scrolloffset < 0)) {
o3_vpos = BELOW;
}
}
if (o3_vpos == ABOVE) {
if (o3_aboveheight == 0) o3_aboveheight = parsedHeight;
placeY = o3_y - (o3_aboveheight+o3_offsety);
if (placeY < scrolloffset) placeY = scrolloffset;
} else {
placeY = o3_y+o3_offsety;
}
if (o3_snapy > 1) {
var snapping = placeY % o3_snapy;
if (o3_aboveheight > 0 && o3_vpos == ABOVE) {
placeY = placeY - (o3_snapy+snapping);
} else {
placeY = placeY+(o3_snapy - snapping);
}
if (placeY < scrolloffset) placeY = scrolloffset;
}
}
return placeY;
}
function checkPositionFlags() {
if (olHautoFlag) olHautoFlag = o3_hauto=0;
if (olVautoFlag) olVautoFlag = o3_vauto=0;
return true;
}
function windowWidth() {
var w;
if (o3_frame.innerWidth) w=o3_frame.innerWidth;
else if (eval('o3_frame.'+docRoot)&&eval("typeof o3_frame."+docRoot+".clientWidth=='number'")&&eval('o3_frame.'+docRoot+'.clientWidth'))
w=eval('o3_frame.'+docRoot+'.clientWidth');
return w;
}
function createDivContainer(id,frm,zValue) {
id = (id || 'overDiv'), frm = (frm || o3_frame), zValue = (zValue || 500);
var objRef, divContainer = layerReference(id);
if (divContainer == null) {
if (olNs4) {
divContainer = frm.document.layers[id] = new Layer(window.innerWidth, frm);
objRef = divContainer;
} else {
var body = (olIe4 ? frm.document.all.tags('BODY')[0] : frm.document.getElementsByTagName("BODY")[0]);
if (olIe4&&!document.getElementById) {
body.insertAdjacentHTML("beforeEnd",'<div id="'+id+'"></div>');
divContainer=layerReference(id);
} else {
divContainer = frm.document.createElement("DIV");
divContainer.id = id;
body.appendChild(divContainer);
}
objRef = divContainer.style;
}
objRef.position = 'absolute';
objRef.visibility = 'hidden';
objRef.zIndex = zValue;
if (olIe4&&!olOp) objRef.left = objRef.top = '0px';
else objRef.left = objRef.top = -10000 + (!olNs4 ? 'px' : 0);
}
var id_name = document.getElementById('overDiv');
id_name.setAttribute("onclick","return nd();");
return divContainer;
}
function layerReference(id) {
return (olNs4 ? o3_frame.document.layers[id] : (document.all ? o3_frame.document.all[id] : o3_frame.document.getElementById(id)));
}
function isFunction(fnRef) {
var rtn = true;
if (typeof fnRef == 'object') {
for (var i = 0; i < fnRef.length; i++) {
if (typeof fnRef[i]=='function') continue;
rtn = false;
break;
}
} else if (typeof fnRef != 'function') {
rtn = false;
}
return rtn;
}
function argToString(array, strtInd, argName) {
var jS = strtInd, aS = '', ar = array;
argName=(argName ? argName : 'ar');
if (ar.length > jS) {
for (var k = jS; k < ar.length; k++) aS += argName+'['+k+'], ';
aS = aS.substring(0, aS.length-2);
}
return aS;
}
function reOrder(hookPt, fnRef, order) {
var newPt = new Array(), match, i, j;
if (!order || typeof order == 'undefined' || typeof order == 'number') return hookPt;
if (typeof order=='function') {
if (typeof fnRef=='object') {
newPt = newPt.concat(fnRef);
} else {
newPt[newPt.length++]=fnRef;
}
for (i = 0; i < hookPt.length; i++) {
match = false;
if (typeof fnRef == 'function' && hookPt[i] == fnRef) {
continue;
} else {
for(j = 0; j < fnRef.length; j++) if (hookPt[i] == fnRef[j]) {
match = true;
break;
}
}
if (!match) newPt[newPt.length++] = hookPt[i];
}
newPt[newPt.length++] = order;
} else if (typeof order == 'object') {
if (typeof fnRef == 'object') {
newPt = newPt.concat(fnRef);
} else {
newPt[newPt.length++] = fnRef;
}
for (j = 0; j < hookPt.length; j++) {
match = false;
if (typeof fnRef == 'function' && hookPt[j] == fnRef) {
continue;
} else {
for (i = 0; i < fnRef.length; i++) if (hookPt[j] == fnRef[i]) {
match = true;
break;
}
}
if (!match) newPt[newPt.length++]=hookPt[j];
}
for (i = 0; i < newPt.length; i++) hookPt[i] = newPt[i];
newPt.length = 0;
for (j = 0; j < hookPt.length; j++) {
match = false;
for (i = 0; i < order.length; i++) {
if (hookPt[j] == order[i]) {
match = true;
break;
}
}
if (!match) newPt[newPt.length++] = hookPt[j];
}
newPt = newPt.concat(order);
}
hookPt = newPt;
return hookPt;
}
function setRunTimeVariables(){
if (typeof runTime != 'undefined' && runTime.length) {
for (var k = 0; k < runTime.length; k++) {
runTime[k]();
}
}
}
function parseCmdLine(pf, i, args) {
if (typeof cmdLine != 'undefined' && cmdLine.length) {
for (var k = 0; k < cmdLine.length; k++) {
var j = cmdLine[k](pf, i, args);
if (j >- 1) {
i = j;
break;
}
}
}
return i;
}
function postParseChecks(pf,args){
if (typeof postParse != 'undefined' && postParse.length) {
for (var k = 0; k < postParse.length; k++) {
if (postParse[k](pf,args)) continue;
return false; // end now since have an error
}
}
return true;
}
function registerCommands(cmdStr) {
if (typeof cmdStr!='string') return;
var pM = cmdStr.split(',');
pms = pms.concat(pM);
for (var i = 0; i< pM.length; i++) {
eval(pM[i].toUpperCase()+'='+pmCount++);
}
}
function registerNoParameterCommands(cmdStr) {
if (!cmdStr && typeof cmdStr != 'string') return;
pmt=(!pmt) ? cmdStr : pmt + ',' + cmdStr;
}
function registerHook(fnHookTo, fnRef, hookType, optPm) {
var hookPt, last = typeof optPm;
if (fnHookTo == 'plgIn'||fnHookTo == 'postParse') return;
if (typeof hookPts[fnHookTo] == 'undefined') hookPts[fnHookTo] = new FunctionReference();
hookPt = hookPts[fnHookTo];
if (hookType != null) {
if (hookType == FREPLACE) {
hookPt.ovload = fnRef; // replace normal overlib routine
if (fnHookTo.indexOf('ol_content_') > -1) hookPt.alt[pms[CSSOFF-1-pmStart]]=fnRef;
} else if (hookType == FBEFORE || hookType == FAFTER) {
var hookPt=(hookType == 1 ? hookPt.before : hookPt.after);
if (typeof fnRef == 'object') {
hookPt = hookPt.concat(fnRef);
} else {
hookPt[hookPt.length++] = fnRef;
}
if (optPm) hookPt = reOrder(hookPt, fnRef, optPm);
} else if (hookType == FALTERNATE) {
if (last=='number') hookPt.alt[pms[optPm-1-pmStart]] = fnRef;
} else if (hookType == FCHAIN) {
hookPt = hookPt.chain;
if (typeof fnRef=='object') hookPt=hookPt.concat(fnRef); // add other functions
else hookPt[hookPt.length++]=fnRef;
}
return;
}
}
function registerPostParseFunction(fn){
if (isFunction(fn)) {
if (typeof fn == 'object') {
postParse = postParse.concat(fn);
} else {
postParse[postParse.length++] = fn;
}
}
}
function runHook(fnHookTo, hookType) {
var l = hookPts[fnHookTo], k, rtnVal = null, optPm, arS, ar = runHook.arguments;
if (hookType == FREPLACE) {
arS = argToString(ar, 2);
if (typeof l == 'undefined' || !(l = l.ovload)) rtnVal = eval(fnHookTo+'('+arS+')');
else rtnVal = eval('l('+arS+')');
} else if (hookType == FBEFORE || hookType == FAFTER) {
if (typeof l != 'undefined') {
l=(hookType == 1 ? l.before : l.after);
if (l.length) {
arS = argToString(ar, 2);
for (var k = 0; k < l.length; k++) eval('l[k]('+arS+')');
}
}
} else if (hookType == FALTERNATE) {
optPm = ar[2];
arS = argToString(ar, 3);
if (typeof l == 'undefined' || (l = l.alt[pms[optPm-1-pmStart]]) == 'undefined') {
rtnVal = eval(fnHookTo+'('+arS+')');
} else {
rtnVal = eval('l('+arS+')');
}
} else if (hookType == FCHAIN) {
arS=argToString(ar,2);
l=l.chain;
for (k=l.length; k > 0; k--) if((rtnVal=eval('l[k-1]('+arS+')'))!=void(0)) break;
}
return rtnVal;
}
function FunctionReference() {
this.ovload = null;
this.before = new Array();
this.after = new Array();
this.alt = new Array();
this.chain = new Array();
}
function Info(version, prerelease) {
this.version = version;
this.prerelease = prerelease;
this.simpleversion = Math.round(this.version*100);
this.major = parseInt(this.simpleversion / 100);
this.minor = parseInt(this.simpleversion / 10) - this.major * 10;
this.revision = parseInt(this.simpleversion) - this.major * 100 - this.minor * 10;
this.meets = meets;
}
function meets(reqdVersion) {
return (!reqdVersion) ? false : this.simpleversion >= Math.round(100*parseFloat(reqdVersion));
}
registerHook("ol_content_simple", ol_content_simple, FALTERNATE, CSSOFF);
registerHook("ol_content_caption", ol_content_caption, FALTERNATE, CSSOFF);
registerHook("ol_content_background", ol_content_background, FALTERNATE, CSSOFF);
registerHook("ol_content_simple", ol_content_simple, FALTERNATE, CSSCLASS);
registerHook("ol_content_caption", ol_content_caption, FALTERNATE, CSSCLASS);
registerHook("ol_content_background", ol_content_background, FALTERNATE, CSSCLASS);
registerPostParseFunction(checkPositionFlags);
registerHook("hideObject", nbspCleanup, FAFTER);
registerHook("horizontalPlacement", horizontalPlacement, FCHAIN);
registerHook("verticalPlacement", verticalPlacement, FCHAIN);
if (olNs4||(olIe5&&isMac)||olKq) olLoaded=1;
registerNoParameterCommands('sticky,autostatus,autostatuscap,fullhtml,hauto,vauto,closeclick,wrap,followmouse,mouseoff,compatmode');
var olCheckMouseCapture=true;
if ((olNs4 || olNs6 || olIe4)) {
olMouseCapture();
} else {
overlib = no_overlib;
nd = no_overlib;
ver3fix = true;
}
function check_common_string(pwd, flag){
var termAlphas = "abcdefghijklmnopqrstuvwxyz";
var termNumerics = "01234567890";
var termSymbols = "~!@#$%^&*()_+";
var termKeyboards1 = "qwertyuiop";
var termKeyboards2 = "asdfghjkl";
var termKeyboards3 = "zxcvbnm";
var termCommon5 = ["123123","abc123","letmein","master","qazwsx","admin"];
var termCommon8 = ["adminpassword","loginpassword","passw0rd","password","useradmin","userpassword"];
var nSeqString = 0;
if(flag == "httpd_password"){ //at lease length 5
if(termAlphas.toLowerCase().indexOf(pwd) != -1 || termAlphas.strReverse().toLowerCase().indexOf(pwd) != -1) { nSeqString++; }
if(termNumerics.toLowerCase().indexOf(pwd) != -1 || termNumerics.strReverse().toLowerCase().indexOf(pwd) != -1) { nSeqString++; }
if(termSymbols.toLowerCase().indexOf(pwd) != -1 || termSymbols.strReverse().toLowerCase().indexOf(pwd) != -1) { nSeqString++; }
if(termKeyboards1.toLowerCase().indexOf(pwd) != -1 || termKeyboards1.strReverse().toLowerCase().indexOf(pwd) != -1) { nSeqString++; }
if(termKeyboards2.toLowerCase().indexOf(pwd) != -1 || termKeyboards2.strReverse().toLowerCase().indexOf(pwd) != -1) { nSeqString++; }
if(termKeyboards3.toLowerCase().indexOf(pwd) != -1 || termKeyboards3.strReverse().toLowerCase().indexOf(pwd) != -1) { nSeqString++; }
for(var s=0;s<termCommon5.length;s++){
if(pwd == termCommon5[s]) { nSeqString++; }
}
for(var t=0;t<termCommon8.length;t++){
if(pwd == termCommon8[t]) { nSeqString++; }
}
}
else if(flag == "wpa_key"){ //at lease length 8
if(termAlphas.toLowerCase().indexOf(pwd) != -1 || termAlphas.strReverse().toLowerCase().indexOf(pwd) != -1) { nSeqString++; }
if(termNumerics.toLowerCase().indexOf(pwd) != -1 || termNumerics.strReverse().toLowerCase().indexOf(pwd) != -1) { nSeqString++; }
if(termSymbols.toLowerCase().indexOf(pwd) != -1 || termSymbols.strReverse().toLowerCase().indexOf(pwd) != -1) { nSeqString++; }
if(termKeyboards1.toLowerCase().indexOf(pwd) != -1 || termKeyboards1.strReverse().toLowerCase().indexOf(pwd) != -1) { nSeqString++; }
if(termKeyboards2.toLowerCase().indexOf(pwd) != -1 || termKeyboards2.strReverse().toLowerCase().indexOf(pwd) != -1) { nSeqString++; }
for(var s=0;s<termCommon8.length;s++){
if(pwd == termCommon8[s]) { nSeqString++; }
}
}
if(pwd == pwd.charAt(0).repeat(pwd.length)) { nSeqString++; }
if(nSeqString > 0)
return true;
else
return false;
}
function chkPass(pwd, flag, obj, id) {
var ttc = '<% nvram_get("territory_code"); %>';
var isSku = function(_ptn){
return (ttc.search(_ptn) == -1) ? false : true;
}
var orig_pwd = "";
var postfix = (id == undefined)? "": ("_" + id);
var oScorebarBorder = document.getElementById("scorebarBorder"+postfix);
var oScorebar = document.getElementById("scorebar"+postfix);
var oScore = document.getElementById("score"+postfix);
if(obj != undefined && (typeof obj == "object")){
oScorebarBorder = $(obj)[0];
oScorebar = $(obj).find(".strength_color")[0];
oScore =$(obj).find(".strength_text")[0];
}
if(flag == "http_passwd" && (isSku("KR") || isSku("SG") || isSku("AA") || secure_default)){
oScorebar.style.display = "none";
return;
}
var nScore=0, nLength=0, nAlphaUC=0, nAlphaLC=0, nNumber=0, nSymbol=0, nMidChar=0, nRequirements=0, nAlphasOnly=0, nNumbersOnly=0, nUnqChar=0, nRepChar=0, nRepInc=0, nConsecAlphaUC=0, nConsecAlphaLC=0, nConsecNumber=0, nConsecSymbol=0, nConsecCharType=0, nSeqAlpha=0, nSeqNumber=0, nSeqSymbol=0, nSeqChar=0, nReqChar=0, nMultConsecCharType=0;
var nMultRepChar=1, nMultConsecSymbol=1;
var nMultMidChar=2, nMultRequirements=2, nMultConsecAlphaUC=2, nMultConsecAlphaLC=2, nMultConsecNumber=2;
var nReqCharType=3, nMultAlphaUC=3, nMultAlphaLC=3, nMultSeqAlpha=3, nMultSeqNumber=3, nMultSeqSymbol=3;
var nMultLength=4, nMultNumber=4;
var nMultSymbol=6;
var nTmpAlphaUC="", nTmpAlphaLC="", nTmpNumber="", nTmpSymbol="";
var sAlphaUC="0", sAlphaLC="0", sNumber="0", sSymbol="0", sMidChar="0", sRequirements="0", sAlphasOnly="0", sNumbersOnly="0", sRepChar="0", sConsecAlphaUC="0", sConsecAlphaLC="0", sConsecNumber="0", sSeqAlpha="0", sSeqNumber="0", sSeqSymbol="0";
var sAlphas = "abcdefghijklmnopqrstuvwxyz";
var sNumerics = "01234567890";
var sSymbols = "~!@#$%^&*()_+";
var sComplexity = "";
var nMinPwdLen = 8;
if (document.all) { var nd = 0; } else { var nd = 1; }
if (pwd) {
nScore = parseInt(pwd.length * nMultLength);
nLength = pwd.length;
var arrPwd = pwd.replace(/\s+/g,"").split(/\s*/);
var arrPwdLen = arrPwd.length;
/* Main calculation for strength:
Loop through password to check for Symbol, Numeric, Lowercase and Uppercase pattern matches */
for (var a=0; a < arrPwdLen; a++) {
if (arrPwd[a].match(/[A-Z]/g)) {
if (nTmpAlphaUC !== "") { if ((nTmpAlphaUC + 1) == a) { nConsecAlphaUC++; nConsecCharType++; } }
nTmpAlphaUC = a;
nAlphaUC++;
}
else if (arrPwd[a].match(/[a-z]/g)) {
if (nTmpAlphaLC !== "") { if ((nTmpAlphaLC + 1) == a) { nConsecAlphaLC++; nConsecCharType++; } }
nTmpAlphaLC = a;
nAlphaLC++;
}
else if (arrPwd[a].match(/[0-9]/g)) {
if (a > 0 && a < (arrPwdLen - 1)) { nMidChar++; }
if (nTmpNumber !== "") { if ((nTmpNumber + 1) == a) { nConsecNumber++; nConsecCharType++; } }
nTmpNumber = a;
nNumber++;
}
else if (arrPwd[a].match(/[^a-zA-Z0-9_]/g)) {
if (a > 0 && a < (arrPwdLen - 1)) { nMidChar++; }
if (nTmpSymbol !== "") { if ((nTmpSymbol + 1) == a) { nConsecSymbol++; nConsecCharType++; } }
nTmpSymbol = a;
nSymbol++;
}
/* Internal loop through password to check for repeat characters */
var bCharExists = false;
for (var b=0; b < arrPwdLen; b++) {
if (arrPwd[a] == arrPwd[b] && a != b) { /* repeat character exists */
bCharExists = true;
/*
Calculate icrement deduction based on proximity to identical characters
Deduction is incremented each time a new match is discovered
Deduction amount is based on total password length divided by the
difference of distance between currently selected match
*/
nRepInc += Math.abs(arrPwdLen/(b-a));
}
}
if (bCharExists) {
nRepChar++;
nUnqChar = arrPwdLen-nRepChar;
nRepInc = (nUnqChar) ? Math.ceil(nRepInc/nUnqChar) : Math.ceil(nRepInc);
}
}
/* Check for sequential alpha string patterns (forward and reverse) */
for (var s=0; s < 23; s++) {
var sFwd = sAlphas.substring(s,parseInt(s+3));
var sRev = sFwd.strReverse();
if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqAlpha++; nSeqChar++;}
}
/* Check for sequential numeric string patterns (forward and reverse) */
for (var s=0; s < 8; s++) {
var sFwd = sNumerics.substring(s,parseInt(s+3));
var sRev = sFwd.strReverse();
if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqNumber++; nSeqChar++;}
}
/* Check for sequential symbol string patterns (forward and reverse) */
for (var s=0; s < 8; s++) {
var sFwd = sSymbols.substring(s,parseInt(s+3));
var sRev = sFwd.strReverse();
if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqSymbol++; nSeqChar++;}
}
/* Modify overall score value based on usage vs requirements */
/* General point assignment */
if (nAlphaUC > 0 && nAlphaUC < nLength) {
nScore = parseInt(nScore + ((nLength - nAlphaUC) * 2));
sAlphaUC = "+ " + parseInt((nLength - nAlphaUC) * 2);
}
if (nAlphaLC > 0 && nAlphaLC < nLength) {
nScore = parseInt(nScore + ((nLength - nAlphaLC) * 2));
sAlphaLC = "+ " + parseInt((nLength - nAlphaLC) * 2);
}
if (nNumber > 0 && nNumber < nLength) {
nScore = parseInt(nScore + (nNumber * nMultNumber));
sNumber = "+ " + parseInt(nNumber * nMultNumber);
}
if (nSymbol > 0) {
nScore = parseInt(nScore + (nSymbol * nMultSymbol));
sSymbol = "+ " + parseInt(nSymbol * nMultSymbol);
}
if (nMidChar > 0) {
nScore = parseInt(nScore + (nMidChar * nMultMidChar));
sMidChar = "+ " + parseInt(nMidChar * nMultMidChar);
}
/* Point deductions for poor practices */
if ((nAlphaLC > 0 || nAlphaUC > 0) && nSymbol === 0 && nNumber === 0) { // Only Letters
nScore = parseInt(nScore - nLength);
nAlphasOnly = nLength;
sAlphasOnly = "- " + nLength;
}
if (nAlphaLC === 0 && nAlphaUC === 0 && nSymbol === 0 && nNumber > 0) { // Only Numbers
nScore = parseInt(nScore - nLength);
nNumbersOnly = nLength;
sNumbersOnly = "- " + nLength;
}
if (nRepChar > 0) { // Same character exists more than once
nScore = parseInt(nScore - nRepInc);
sRepChar = "- " + nRepInc;
}
if (nConsecAlphaUC > 0) { // Consecutive Uppercase Letters exist
nScore = parseInt(nScore - (nConsecAlphaUC * nMultConsecAlphaUC));
sConsecAlphaUC = "- " + parseInt(nConsecAlphaUC * nMultConsecAlphaUC);
}
if (nConsecAlphaLC > 0) { // Consecutive Lowercase Letters exist
nScore = parseInt(nScore - (nConsecAlphaLC * nMultConsecAlphaLC));
sConsecAlphaLC = "- " + parseInt(nConsecAlphaLC * nMultConsecAlphaLC);
}
if (nConsecNumber > 0) { // Consecutive Numbers exist
nScore = parseInt(nScore - (nConsecNumber * nMultConsecNumber));
sConsecNumber = "- " + parseInt(nConsecNumber * nMultConsecNumber);
}
if (nSeqAlpha > 0) { // Sequential alpha strings exist (3 characters or more)
nScore = parseInt(nScore - (nSeqAlpha * nMultSeqAlpha));
sSeqAlpha = "- " + parseInt(nSeqAlpha * nMultSeqAlpha);
}
if (nSeqNumber > 0) { // Sequential numeric strings exist (3 characters or more)
nScore = parseInt(nScore - (nSeqNumber * nMultSeqNumber));
sSeqNumber = "- " + parseInt(nSeqNumber * nMultSeqNumber);
}
if (nSeqSymbol > 0) { // Sequential symbol strings exist (3 characters or more)
nScore = parseInt(nScore - (nSeqSymbol * nMultSeqSymbol));
sSeqSymbol = "- " + parseInt(nSeqSymbol * nMultSeqSymbol);
}
/* Determine complexity based on overall score */
if (nScore > 100) { nScore = 100; } else if (nScore < 0) { nScore = 0; }
if(typeof document.forms[0] == "undefined" || (typeof document.forms[0] != "undefined" && document.form.current_page.value != "AiProtection_HomeProtection.asp")){
if (nScore >= 0 && nScore < 20) { sComplexity = "<#1415#>"; }
else if (nScore >= 20 && nScore < 40) { sComplexity = "<#582#>"; }
else if (nScore >= 40 && nScore < 60) { sComplexity = "<#583#>"; }
else if (nScore >= 60 && nScore < 80) { sComplexity = "<#584#>"; }
else if (nScore >= 80 && nScore <= 100) { sComplexity = "<#585#>"; }
}
else{
if (nScore >= 0 && nScore < 20) { sComplexity = "<a href='Advanced_Wireless_Content.asp' target='_blank'><#581#></a>"; }
else if (nScore >= 20 && nScore < 40) { sComplexity = "<a href='Advanced_Wireless_Content.asp' target='_blank'><#582#></a>"; }
else if (nScore >= 40 && nScore < 60) { sComplexity = "<a href='Advanced_Wireless_Content.asp' target='_blank'><#583#></a>"; }
else if (nScore >= 60 && nScore < 80) { sComplexity = "<a href='Advanced_Wireless_Content.asp' target='_blank'><#584#></a>"; }
else if (nScore >= 80 && nScore <= 100) { sComplexity = "<a href='Advanced_Wireless_Content.asp' target='_blank'><#585#></a>"; }
}
/* Display updated score criteria to client */
if(typeof document.forms[0] == "undefined" || (typeof document.forms[0] != "undefined" && document.form.current_page.value != "AiProtection_HomeProtection.asp")){ //for Router weakness status, Jimeing added at 2014/06/07
oScorebarBorder.style.display = "flex";
oScorebar.style.backgroundPosition = parseInt(nScore) + "%";
}
else{
if(nScore >= 0 && nScore < 40){
oScore.className = "status_no";
}
else if(nScore >= 40 && nScore <= 100){
oScore.className = "status_yes";
}
}
if(oScore == null){
oScorebar.innerHTML = sComplexity;
}
else{
oScore.innerHTML = sComplexity;
}
}
else {
/* Display default score criteria to client */
if(flag == 'http_passwd'){
chkPass(" ", 'http_passwd', obj, id);
}
else
chkPass(" ", "", obj, id);
}
}
String.prototype.strReverse = function() {
var newstring = "";
for (var s=0; s < this.length; s++) {
newstring = this.charAt(s) + newstring;
}
return newstring;
};
function goToWAN(index){
document.titleForm.wan_unit.disabled = false;
document.titleForm.wan_unit.value = index;
if(index == usb_index){
if(gobi_support)
document.titleForm.current_page.value = "Advanced_MobileBroadband_Content.asp?af=pincode";
else
document.titleForm.current_page.value = "Advanced_Modem_Content.asp";
}
else if(index == dsl_index)
document.titleForm.current_page.value = "Advanced_DSL_Content.asp";
else
document.titleForm.current_page.value = "Advanced_WAN_Content.asp";
document.titleForm.action_mode.value = "change_wan_unit";
document.titleForm.action = "apply.cgi";
document.titleForm.target = "";
document.titleForm.submit();
}

