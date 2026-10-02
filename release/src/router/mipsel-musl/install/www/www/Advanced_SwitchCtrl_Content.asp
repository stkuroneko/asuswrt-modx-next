<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title><#971#> - <#3503#></title>
<link rel="stylesheet" type="text/css" href="index_style.css">
<link rel="stylesheet" type="text/css" href="form_style.css">
<link rel="stylesheet" type="text/css" href="other.css">
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" language="JavaScript" src="/validator.js"></script>
<script type="text/javascript" src="/js/jquery.js"></script>
<style>
.perNode_app_table{
width: 740px;
position: absolute;
left: 50%;
margin-top: 30px;
margin-left: -370px;
}
</style>
<script>
var lacp_support = isSupport("lacp");
var lacp_enabled = '<% nvram_get("lacp_enabled"); %>' == 1 ?true: false;
var bonding_policy_support = false;
if( lacp_support
&& (based_modelid == "GT-AC5300" || based_modelid == "RT-AC86U" || based_modelid == "GT-AC2900" || based_modelid == "RT-AC87U" || based_modelid == "RT-AC5300" || based_modelid == "RT-AC88U" || based_modelid == "RT-AC3100")){
bonding_policy_support = true;
var bonding_policy_value = '<% nvram_get("bonding_policy"); %>';
}
var jumbo_frame_enable_ori = '<% nvram_get("jumbo_frame_enable"); %>';
var ctf_disable_force_ori = '<% nvram_get("ctf_disable"); %>';
var lacp_enabled_ori = '<% nvram_get("lacp_enabled"); %>';
var wans_lanport = '<% nvram_get("wans_lanport"); %>';
var iptv_port_settings_orig = '<%nvram_get("iptv_port_settings"); %>' == ""? "12": '<%nvram_get("iptv_port_settings"); %>';
var switch_wantag_orig = '<% nvram_get("switch_wantag"); %>';
var switch_stb_x_orig = '<% nvram_get("switch_stb_x"); %>';
var no_jumbo_frame_support = isSupport("no_jumbo_frame");
function disable_lacp_if_conflicts_with_iptv(){
if((based_modelid == "RT-AX89U" || based_modelid == "GT-AXY16000")){
if(switch_stb_x_orig == "1" || switch_stb_x_orig == "2" || switch_stb_x_orig == "5"){
var note_str = "This function is disabled because LAN1 or LAN2 is configured as IPTV STB port."; //untranslated
document.form.lacp_enabled.style.display = "none";
document.getElementById("lacp_note").innerHTML = note_str;
document.getElementById("lacp_desc").style.display = "";
document.form.lacp_enabled.value = "0";
}
}
else if(based_modelid == "XT8PRO"){
if(switch_stb_x_orig == "2" || switch_stb_x_orig == "3" || switch_stb_x_orig == "5" || switch_stb_x_orig == "6" || switch_stb_x_orig == "8"){
var note_str = "This function is disabled because LAN2 or LAN3 is configured as IPTV STB port."; //untranslated
document.form.lacp_enabled.style.display = "none";
document.getElementById("lacp_note").innerHTML = note_str;
document.getElementById("lacp_desc").style.display = "";
document.form.lacp_enabled.value = "0";
}
}
}
function initial(){
if((based_modelid == "RT-AX89U" || based_modelid == "GT-AXY16000")){
var wans_dualwan_array = '<% nvram_get("wans_dualwan"); %>'.split(" ");
document.form.aqr_hwnat_type.disabled = false;
document.form.aqr_link_speed.disabled = false;
document.form.aqr_ipg.disabled = false;
document.form.sfpp_hwnat_type.disabled = false;
document.form.sfpp_max_speed.disabled = false;
document.form.sfpp_force_on.disabled = false;
document.form.sfpp_module_ipaddr.disabled = false;
document.getElementById("sfpp_module_ipaddr").style.color = "#FFFFFF";
document.getElementById("aqr_sfpp_table").style.display = "";
if (wans_dualwan_array.indexOf("sfp+") == -1) {
document.form.sfpp_module_ipaddr.disabled = true;
document.getElementById("sfpp_module_ipaddr").style.color = "#8C8C8C";
}
if (sw_mode != "1") {
document.getElementById("sfpp_ipaddr_tr").style.display = "none";
}
}
if(qca_support){
var nataccel = '<% nvram_get("qca_sfe"); %>';
var nataccel_status = '<% nat_accel_status(); %>';
if(nataccel == '1' && nataccel_status == '1'){
document.getElementById("natAccelDesc").innerHTML = "<#3010#>";
}
else{
document.getElementById("natAccelDesc").innerHTML = "<#3006#>";
}
}
else if(mtk_support){
var nataccel = '<% nvram_get("hwnat"); %>';
var nataccel_status = '<% nat_accel_status(); %>';
if(nataccel == '1' && nataccel_status == '1'){
document.getElementById("MTKnatAccelDesc").innerHTML = "<#3010#>";
}
else{
document.getElementById("MTKnatAccelDesc").innerHTML = "<#3006#>";
}
}
else{
var ctf_disable = '<% nvram_get("ctf_disable"); %>';
var ctf_fa_mode = '<% nvram_get("ctf_fa_mode"); %>';
if(ctf_disable == 1){
document.getElementById("ctfLevelDesc").innerHTML = "<#3006#>";
}
else{
if(ctf_fa_mode == '2')
document.getElementById("ctfLevelDesc").innerHTML = "<#3008#>";
else
document.getElementById("ctfLevelDesc").innerHTML = "<#3007#>";
}
}
if (re_mode == "1"){
$("#tabMenu").addClass("perNode_app_table");
$(".submenuBlock").css("margin-top", "initial");
show_loading_obj();
} else {
$("#content_table").addClass("content");
$("#tabMenu").addClass("app_table app_table_usb");
show_menu();
}
$("#tabMenu").css("display", "");
if(lacp_support){
document.getElementById("lacp_tr").style.display = "";
document.form.lacp_enabled.disabled = false;
if(lacp_enabled){
document.getElementById("lacp_desc").style.display = "";
if(bonding_policy_support){
document.form.bonding_policy.value = bonding_policy_value;
check_bonding_policy(document.form.lacp_enabled);
}
}
else
document.getElementById("lacp_desc").style.display = "none";
}
else{
document.form.lacp_enabled.disabled = true;
document.form.bonding_policy.disabled = true;
}
if(qca_support){
if(lyra_hide_support){
document.getElementById("jumbo_tr").style.display = "none";
document.form.jumbo_frame_enable.disabled = true;
}
if(wifison_ready != "1" && sw_mode == "1"){
document.getElementById("qca_tr").style.display = "";
document.form.qca_sfe.disabled = false;
}
}
else if(mtk_support || based_modelid == "RT-ACRH18" || based_modelid == "4G-AC86U" || based_modelid == "4G-AX56" || based_modelid == "RT-AX53U" || based_modelid == "RT-AX54" || based_modelid == "XD4S"){//MTK
document.getElementById("mtk_tr").style.display = "";
document.form.hwnat.disabled = false;
document.getElementById("ctf_tr").style.display = "none";
document.form.ctf_disable_force.disabled = true;
}
else{
if(based_modelid == "GT-AC5300"){
var new_str = "";
new_str = document.getElementById("lacp_note").innerHTML.replace(/LAN1/g, "LAN5");
document.getElementById("lacp_note").innerHTML = new_str.replace(/LAN2/g, "LAN6");
}
else if(based_modelid == "XT8PRO"){
var new_str = "";
new_str = document.getElementById("lacp_note").innerHTML.replace(/LAN1/g, "LAN3");
document.getElementById("lacp_note").innerHTML = new_str;
}
if(hnd_support){
document.getElementById("ctf_tr").style.display = "none";
document.form.ctf_disable_force.disabled = true;
}
else{
if(sw_mode == "1" || sw_mode == "5"){
document.getElementById("ctf_tr").style.display = "";
document.form.ctf_disable_force.disabled = false;
}
}
}
if(lacp_support && wans_dualwan_array.indexOf("lan") != -1){
var wan_lanport_text = "";
if(based_modelid == "GT-AC5300")
var bonding_port_settings = [{"val": "4", "text": "LAN5"}, {"val": "3", "text": "LAN6"}];
else if(based_modelid == "RT-AC86U" || based_modelid == "GT-AC2900")
var bonding_port_settings = [{"val": "4", "text": "LAN1"}, {"val": "3", "text": "LAN2"}];
else if(based_modelid == "XT8PRO")
var bonding_port_settings = [{"val": "2", "text": "LAN2"}, {"val": "3", "text": "LAN3"}];
else
var bonding_port_settings = [{"val": "1", "text": "LAN1"}, {"val": "2", "text": "LAN2"}];
for(var i = 0; i < bonding_port_settings.length; i++){
if(wans_lanport == bonding_port_settings[i].val){
wan_lanport_text = bonding_port_settings[i].text.toUpperCase();
}
}
if(wan_lanport_text!= ""){
var note_str = "This function is disabled because " + wan_lanport_text + " is configured as WAN. If you want to enable it, please click <a href=\"http://<#973#>/Advanced_WANPort_Content.asp\" target=\"_blank\" style=\"text-decoration:underline;\">here</a> to change dual wan settings."; //untranslated
document.form.lacp_enabled.style.display = "none";
document.getElementById("lacp_note").innerHTML = note_str;
document.getElementById("lacp_desc").style.display = "";
document.form.lacp_enabled.disabled = true;
}
}
disable_lacp_if_conflicts_with_iptv();
if(no_jumbo_frame_support)
$("#jumbo_tr").hide();
}
function applyRule(){
var setting_changed = false;
if((jumbo_frame_enable_ori != document.form.jumbo_frame_enable.value)
|| (ctf_disable_force_ori != document.form.ctf_disable_force.value)
|| (lacp_enabled_ori != document.form.lacp_enabled.value) ){
setting_changed = true
}
if(based_modelid == "GT-AC5300" && (lacp_enabled_ori != document.form.lacp_enabled.value)){
var msg = "Enable Bonding/ Link aggregation will change settings of IPTV/ VOIP ports on IPTV page to LAN1/ LAN2. Are you sure to do it?";//untranslated
if(document.form.lacp_enabled.value == "1" && iptv_port_settings_orig == "56"){
if(confirm(msg)){
document.form.iptv_port_settings.disabled = false;
document.form.iptv_port_settings.value = "12";
}
else{
document.form.lacp_enabled.value = "0";
check_bonding_policy(document.form.lacp_enabled);
document.form.lacp_enabled.focus();
return;
}
}
}
if (based_modelid == "RT-AX89U") {
var lan_netmask = inet_network('<% nvram_get("lan_netmask"); %>');
if (document.form.sfpp_module_ipaddr.value != "" && document.form.sfpp_force_on.value == "0")
document.form.sfpp_force_on.value = "1";
if ((document.form.sfpp_module_ipaddr.value == '<% nvram_get("lan_ipaddr"); %>')
|| ((inet_network(document.form.sfpp_module_ipaddr.value) & lan_netmask)
== (inet_network('<% nvram_get("lan_ipaddr"); %>') & lan_netmask))) {
alert(document.form.sfpp_module_ipaddr.value + " conflicts with LAN IP address!");
return false;
}
}
if(!setting_changed){ // only change the bonding policy
document.form.action_script.value = "restart_net_and_phy";
document.form.action_wait.value = "35";
}
if(lantiq_support){
document.form.action_script.value = "restart_wan_if;restart_firewall";
document.form.action_wait.value = "10";
if(!setting_changed){ // only change the bonding policy
document.form.action_script.value += ";restart_net_and_phy";
document.form.action_wait.value = "35";
}
}
if(document.form.action_script.value == "reboot"){
if(confirm("<#65#>")){
showLoading();
document.form.submit();
}
}
else{
showLoading();
document.form.submit();
}
}
function check_bonding_policy(obj){
if(obj.value == "1"){
if(bonding_policy_support){
document.getElementById("lacp_policy_tr").style.display = "";
document.form.bonding_policy.disabled = false;
}
document.getElementById("lacp_desc").style.display = "";
}
else{
if(bonding_policy_support){
document.getElementById("lacp_policy_tr").style.display = "none";
document.form.bonding_policy.disabled = true;
}
document.getElementById("lacp_desc").style.display = "none";
}
}
</script>
</head>
<body onload="initial();" onunLoad="return unload_body();" class="bg">
<div id="TopBanner"></div>
<div id="hiddenMask" class="popup_bg">
<table cellpadding="5" cellspacing="0" id="dr_sweet_advise" class="dr_sweet_advise" align="center">
<tr>
<td>
<div class="drword" id="drword" style="height:110px;"><#476#> <#473#>...
<br/>
<br/>
</div>
<div class="drImg"><img src="images/alertImg.png"></div>
<div style="height:70px;"></div>
</td>
</tr>
</table>
<!--[if lte IE 6.5]><iframe class="hackiframe"></iframe><![endif]-->
</div>
<div id="Loading" class="popup_bg"></div>
<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>
<form method="post" name="form" id="ruleForm" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="productid" value="<% nvram_get("productid"); %>">
<input type="hidden" name="current_page" value="Advanced_SwitchCtrl_Content.asp">
<input type="hidden" name="next_page" value="Advanced_SwitchCtrl_Content.asp">
<input type="hidden" name="modified" value="0">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_script" value="reboot">
<input type="hidden" name="action_wait" value="<% nvram_get("reboot_time"); %>">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">
<input type="hidden" name="iptv_port_settings" value="<% nvram_get("iptv_port_settings"); %>" disabled>
<table id="content_table" align="center" cellspacing="0" style="margin:auto;">
<tr>
<td width="17">&nbsp;</td>
<td valign="top" width="202">
<div id="mainMenu"></div>
<div id="subMenu"></div>
</td>
<td valign="top">
<div id="tabMenu" class="submenuBlock"></div>
<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0">
<tr>
<td align="left" valign="top">
<table width="760px" border="0" cellpadding="5" cellspacing="0" class="FormTitle" id="FormTitle">
<tbody>
<tr>
<td bgcolor="#4D595D" valign="top">
<div>&nbsp;</div>
<div class="formfonttitle"><#494#> - <#3503#></div>
<div style="margin:10px 0 10px 5px;" class="splitLine"></div>
<div class="formfontdesc"><#3507#></div>
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
<tr id="jumbo_tr">
<th><#2722#></th>
<td>
<select name="jumbo_frame_enable" class="input_option">
<option class="content_input_fd" value="0" <% nvram_match("jumbo_frame_enable", "0","selected"); %>><#4183#></option>
<option class="content_input_fd" value="1" <% nvram_match("jumbo_frame_enable", "1","selected"); %>><#4182#></option>
</select>
</td>
</tr>
<tr id="ctf_tr" style="display: none;">
<th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(29,2);"><#3004#></a></th>
<td>
<select name="ctf_disable_force" class="input_option" disabled>
<option class="content_input_fd" value="1" <% nvram_match("ctf_disable_force", "1","selected"); %>><#4183#></option>
<option class="content_input_fd" value="0" <% nvram_match("ctf_disable_force", "0","selected"); %>><#244#></option>
</select>
&nbsp
<span id="ctfLevelDesc"></span>
</td>
</tr>
<tr id="qca_tr" style="display: none;">
<th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(29,2);"><#3004#></a></th>
<td>
<select name="qca_sfe" class="input_option" disabled>
<option class="content_input_fd" value="0" <% nvram_match("qca_sfe", "0","selected"); %>><#4183#></option>
<option class="content_input_fd" value="1" <% nvram_match("qca_sfe", "1","selected"); %>><#4182#></option>
</select>
&nbsp
<span id="natAccelDesc"></span>
</td>
</tr>
<tr id="mtk_tr" style="display: none;">
<th><#3004#></th>
<td>
<select name="hwnat" class="input_option" disabled>
<option class="content_input_fd" value="0" <% nvram_match("hwnat", "0","selected"); %>><#4183#></option>
<option class="content_input_fd" value="1" <% nvram_match("hwnat", "1","selected"); %>><#244#></option>
</select>
&nbsp
<span id="MTKnatAccelDesc"></span>
</td>
</tr>
<tr style="display:none">
<th><#3508#></th>
<td>
<input type="radio" name="gro_disable_force" value="0" <% nvram_match("gro_disable_force", "0", "checked"); %>><#278#>
<input type="radio" name="gro_disable_force" value="1" <% nvram_match("gro_disable_force", "1", "checked"); %>><#277#>
</td>
</tr>
<tr id="lacp_tr" style="display:none;">
<th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(29,1);"><#3015#></a></th>
<td>
<select name="lacp_enabled" class="input_option" onchange="check_bonding_policy(this);" disabled>
<option class="content_input_fd" value="0" <% nvram_match("lacp_enabled", "0","selected"); %>><#4183#></option>
<option class="content_input_fd" value="1" <% nvram_match("lacp_enabled", "1","selected"); %>><#4182#></option>
</select>
<div id="lacp_desc" style="display:none"><span id="lacp_note"><#3018#></span><div>
</td>
</tr>
<tr id="lacp_policy_tr" style="display:none">
<th><#3504#></th>
<td>
<select name="bonding_policy" class="input_option" disabled>
<option value="0"><#1802#></option>
<option value="1"><#3506#></option>
<option value="2"><#3505#></option>
</select>
</td>
</tr>
</table>
<table id="aqr_sfpp_table" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" style="display:none">
<thead>
<tr id="aqr_title_field">
<td id="aqr_title" colspan="2">10G base-T port</td>
</tr>
</thead>
<tr id="aqr_hwnat_type_tr">
<th>Acceleration type</th><td>
<select name="aqr_hwnat_type" class="input_option" disabled>
<option value="0" <% nvram_match("aqr_hwnat_type", "0","selected"); %>><#244#></option>
<option value="1" <% nvram_match("aqr_hwnat_type", "1","selected"); %>>PPE + NSS</option>
<option value="2" <% nvram_match("aqr_hwnat_type", "2","selected"); %>>NSS</option>
</select>
</td>
</tr>
<tr id="aqr_link_speed_tr">
<th>Link speed</th><td>
<select name="aqr_link_speed" class="input_option" disabled>
<option value="0" <% nvram_match("aqr_link_speed", "0","selected"); %>><#244#></option>
<option value="1000" <% nvram_match("aqr_link_speed", "1000","selected"); %>>1Gbps</option>
<option value="2500" <% nvram_match("aqr_link_speed", "2500","selected"); %>>2.5Gbps</option>
<option value="5000" <% nvram_match("aqr_link_speed", "5000","selected"); %>>5Gbps</option>
<option value="10000" <% nvram_match("aqr_link_speed", "10000","selected"); %>>10Gbps</option>
</select>
</td>
</tr>
<tr id="aqr_ipg_tr">
<th>Interpacket gap</th><td>
<select name="aqr_ipg" class="input_option" disabled>
<option value="96" <% nvram_match("aqr_ipg", "96","selected"); %>><#1802#></option>
<option value="128" <% nvram_match("aqr_ipg", "128","selected"); %>>128 bit times</option>
</select>
</td>
</tr>
<thead>
<tr id="sfpp_title_field">
<td id="sfpp_title" colspan="2">10G SFP+ port</td>
</tr>
</thead>
<tr id="sfpp_hwnat_type_tr">
<th>Acceleration type</th><td>
<select name="sfpp_hwnat_type" class="input_option" disabled>
<option value="0" <% nvram_match("sfpp_hwnat_type", "0","selected"); %>><#244#></option>
<option value="1" <% nvram_match("sfpp_hwnat_type", "1","selected"); %>>PPE + NSS</option>
<option value="2" <% nvram_match("sfpp_hwnat_type", "2","selected"); %>>NSS</option>
</select>
</td>
</tr>
<tr id="sfpp_max_speed_tr">
<th>Link speed</th><td>
<select name="sfpp_max_speed" class="input_option" disabled>
<option value="0" <% nvram_match("sfpp_max_speed", "0","selected"); %>><#244#></option>
<option value="1000" <% nvram_match("sfpp_max_speed", "1000","selected"); %>>1Gbps</option>
<option value="10000" <% nvram_match("sfpp_max_speed", "10000","selected"); %>>10Gbps</option>
</select>
</td>
</tr>
<tr id="sfpp_force_on_tr">
<th>TX clock</th><td>
<input type="radio" name="sfpp_force_on" value="0" <% nvram_match("sfpp_force_on", "0", "checked"); %>><#244#>
<input type="radio" name="sfpp_force_on" value="1" <% nvram_match("sfpp_force_on", "1", "checked"); %>>ON</td>
</tr>
<tr id="sfpp_ipaddr_tr">
<th><a class="hintstyle" href="javascript:void(0);" onClick="overlib('IP address of GPON module, e.g., 192.168.1.1 for ZTE ZXHN F5716G. You can access telnet or web server of GPON module if it exist via LAN/WLAN devices by configuring this setting. SFP+ port must be primary WAN or secondary WAN.');" onmouseout="nd();">GPON module's IP address</th><td>
<input type="text" id="sfpp_module_ipaddr" name="sfpp_module_ipaddr" value="<% nvram_get("sfpp_module_ipaddr"); %>" tabindex="3" onKeyPress="return validator.isIPAddr(this, event);" maxlength="15" class="input_15_table" autocorrect="off" autocapitalize="off">
</td>
</tr>
</table>
<div class="apply_gen">
<input class="button_gen" onclick="applyRule()" type="button" value="<#287#>"/>
</div>
</td>
</tr>
</tbody>
</table>
</td>
</tr>
</table>
</td>
<td width="10" align="center" valign="top">&nbsp;</td>
</tr>
</table>
</form>
<div id="footer"></div>
</body>
</html>

