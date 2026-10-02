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
<title><#971#> - <#2886#></title>
<link rel="stylesheet" type="text/css" href="/index_style.css">
<link rel="stylesheet" type="text/css" href="/form_style.css">
<script type="text/javascript" src="/js/jquery.js"></script>
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/validator.js"></script>
<script>var qos_orates = '<% nvram_get("qos_orates"); %>';
var qos_irates = '<% nvram_get("qos_irates"); %>';
function initial(){
show_menu();
if(bwdpi_support){
document.getElementById('content_title').innerHTML = "<#2886#> - <#2069#>";
}
else{
document.getElementById('content_title').innerHTML = "<#483#> - QoS";
}
init_changeScale("qos_obw");
init_changeScale("qos_ibw");
if('<% nvram_get("qos_enable"); %>' == "1")
document.getElementById('is_qos_enable_desc').style.display = "none";
}
function init_changeScale(_obj_String){
if(document.getElementById(_obj_String).value > 999){
document.getElementById(_obj_String+"_scale").value = "Mb/s";
document.getElementById(_obj_String).value = Math.round((document.getElementById(_obj_String).value/1024)*100)/100;
}
gen_options();
}
function changeScale(_obj_String){
if(document.getElementById(_obj_String+"_scale").value == "Mb/s")
document.getElementById(_obj_String).value = Math.round((document.getElementById(_obj_String).value/1024)*100)/100;
else
document.getElementById(_obj_String).value = Math.round(document.getElementById(_obj_String).value*1024);
gen_options();
}
function applyRule(){
if(save_options() != false){
if(document.getElementById("qos_obw_scale").value == "Mb/s"){
document.form.qos_obw.value = document.form.qos_obw_orig.value;
}
if(document.getElementById("qos_ibw_scale").value == "Mb/s"){
document.form.qos_ibw.value = document.form.qos_ibw_orig.value;
}
save_checkbox();
showLoading();
document.form.submit();
}
}
function save_checkbox(){
document.form.qos_ack.value = document.form.qos_ack_checkbox.checked ? "on" : "off";
document.form.qos_syn.value = document.form.qos_syn_checkbox.checked ? "on" : "off";
document.form.qos_fin.value = document.form.qos_fin_checkbox.checked ? "on" : "off";
document.form.qos_rst.value = document.form.qos_rst_checkbox.checked ? "on" : "off";
document.form.qos_icmp.value = document.form.qos_icmp_checkbox.checked ? "on" : "off";
}
function save_options(){
document.form.qos_orates.value = "";
for(var j=0; j<5; j++){
var upload_bw_max = eval("document.form.upload_bw_max_"+j);
var upload_bw_min = eval("document.form.upload_bw_min_"+j);
var download_bw_max = eval("document.form.download_bw_max_"+j);
if(parseInt(upload_bw_max.value) < parseInt(upload_bw_min.value)){
alert("<#3252#>");
upload_bw_max.focus();
return false;
}
document.form.qos_orates.value += upload_bw_min.value + "-" + upload_bw_max.value + ",";
document.form.qos_irates.value += download_bw_max.value + ",";
}
document.form.qos_orates.value += "0-0,0-0,0-0,0-0,0-0";
document.form.qos_irates.value += "0,0,0,0,0";
return true;
}
function done_validating(action){
refreshpage();
}
function addRow(obj, head){
if(head == 1)
qos_rulelist_array += "<"
else
qos_rulelist_array += ">"
qos_rulelist_array += obj.value;
obj.value= "";
document.form.qos_min_transferred_x_0.value= "";
document.form.qos_max_transferred_x_0.value= "";
}
function validForm(){
if(!Block_chars(document.form.qos_service_name_x_0, ["<" ,">" ,"'" ,"%"])){
return false;
}
if(!valid_IPorMAC(document.form.qos_ip_x_0)){
return false;
}
replace_symbol();
if(document.form.qos_port_x_0.value != "" && !Check_multi_range(document.form.qos_port_x_0, 1, 65535)){
parse_port="";
return false;
}
if(document.form.qos_max_transferred_x_0.value.length > 0
&& document.form.qos_max_transferred_x_0.value < document.form.qos_min_transferred_x_0.value){
document.form.qos_max_transferred_x_0.focus();
alert("<#3797#> "+document.form.qos_min_transferred_x_0.value);
return false;
}
return true;
}
function conv_to_transf(){
if(document.form.qos_min_transferred_x_0.value == "" && document.form.qos_max_transferred_x_0.value =="")
document.form.qos_transferred_x_0.value = "";
else
document.form.qos_transferred_x_0.value = document.form.qos_min_transferred_x_0.value + "~" + document.form.qos_max_transferred_x_0.value;
}
function gen_options(){
if(document.getElementById("upload_bw_min_0").innerHTML == ""){
var qos_orates_row = qos_orates.split(',');
var qos_irates_row = qos_irates.split(',');
for(var j=0; j<5; j++){
var upload_bw_max = eval("document.form.upload_bw_max_"+j);
var upload_bw_min = eval("document.form.upload_bw_min_"+j);
var download_bw_max = eval("document.form.download_bw_max_"+j);
var qos_orates_col = qos_orates_row[j].split('-');
var qos_irates_col = qos_irates_row[j].split('-');
for(var i=0; i<101; i++){
add_options_value(upload_bw_min, i, qos_orates_col[0]);
add_options_value(upload_bw_max, i, qos_orates_col[1]);
add_options_value(download_bw_max, i, qos_irates_col[0]);
}
var upload_bw_desc = eval('document.getElementById("upload_bw_'+j+'_desc")');
var download_bw_desc = eval('document.getElementById("download_bw_'+j+'_desc")');
}
}
else{
for(var j=0; j<5; j++){
var upload_bw_max = eval("document.form.upload_bw_max_"+j);
var upload_bw_min = eval("document.form.upload_bw_min_"+j);
var download_bw_max = eval("document.form.download_bw_max_"+j);
var upload_bw_desc = eval('document.getElementById("upload_bw_'+j+'_desc")');
var download_bw_desc = eval('document.getElementById("download_bw_'+j+'_desc")');
upload_bw_desc.innerHTML = Math.round(upload_bw_min.value*document.form.qos_obw_orig.value)/100 + " ~ " + Math.round(upload_bw_max.value*document.form.qos_obw_orig.value)/100 + " " + document.getElementById("qos_obw_scale").value;
download_bw_desc.innerHTML = "0 ~ " + Math.round(download_bw_max.value*document.form.qos_ibw_orig.value)/100 + " " + document.getElementById("qos_ibw_scale").value;
}
}
}
function add_options_value(o, arr, orig){
if(orig == arr)
add_option(o, arr, arr, 1);
else
add_option(o, arr, arr, 0);
}
function switchPage(page){
if(page == "1")
location.href = "/QoS_EZQoS.asp";
else if(page == "2")
location.href = "/Advanced_QOSUserRules_Content.asp";
else
return false;
}
</script>
</head>
<body onLoad="initial();" onunLoad="return unload_body();" class="bg">
<div id="TopBanner"></div>
<div id="Loading" class="popup_bg"></div>
<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>
<form method="post" name="form" id="ruleForm" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="current_page" value="Advanced_QOSUserPrio_Content.asp">
<input type="hidden" name="next_page" value="">
<input type="hidden" name="modified" value="0">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_wait" value="5">
<input type="hidden" name="action_script" value="restart_qos;restart_firewall">
<input type="hidden" name="first_time" value="">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">
<input type="hidden" name="qos_orates" value=''>
<input type="hidden" name="qos_irates" value=''>
<input type="hidden" name="qos_obw_orig" id="qos_obw" value="<% nvram_get("qos_obw"); %>">
<input type="hidden" name="qos_ibw_orig" id="qos_ibw" value="<% nvram_get("qos_ibw"); %>">
<table class="content" align="center" cellpadding="0" cellspacing="0">
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
<td>
<table width="760px" border="0" cellpadding="4" cellspacing="0" class="FormTitle" id="FormTitle">
<tr>
<td bgcolor="#4D595D" valign="top">
<table>
<tr>
<td>
<table width="100%" >
<tr >
<td class="formfonttitle" align="left">
<div id="content_title" style="margin-top:5px;"></div>
</td>
<td align="right" >
<div style="margin-top:5px;">
<select onchange="switchPage(this.options[this.selectedIndex].value)" class="input_option">
<!--option><#3523#></option-->
<option value="1"><#1028#></option>
<option value="2"><#3256#></option>
<option value="3" selected><#3255#></option>
</select>
</div>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td height="5"><div class="splitLine"></div></td>
</tr>
<tr>
<td style="font-style: italic;font-size: 14px;">
<div class="formfontdesc"><#3775#></div>
<div class="formfontdesc" id="is_qos_enable_desc" style="color:#FFCC00;"><#3776#></div>
</td>
</tr>
<tr><td>
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
<thead>
<tr>
<td colspan="2"><div><#3372#></div></td>
</tr>
</thead>
<tr>
<td>
<table width="100%" border="0" cellpadding="4" cellspacing="0">
<tr>
<td width="58%" style="font-size:12px; border-collapse: collapse;border:0; padding-left:0;">
<table width="100%" border="0" cellpadding="4" cellspacing="0" style="font-size:12px; border-collapse: collapse;border:0;">
<thead>
<tr>
<td colspan="4" ><#3726#></td>
</tr>
<tr style="height: 55px;">
<th style="width:22%;line-height:15px;color:#FFFFFF;"><#3728#></th>
<th style="width:25%;line-height:15px;color:#FFFFFF;"><a href="javascript:void(0);" onClick="openHint(20,3);"><div class="table_text"><#2891#></div></a></th>
<th style="width:26%;line-height:15px;color:#FFFFFF;"><a href="javascript:void(0);" onClick="openHint(20,4);"><div class="table_text"><#2874#></div></a></th>
<th style="width:27%;line-height:15px;color:#FFFFFF;"><#1830#></th>
</tr>
</thead>
<tr>
<th style="width:22%;line-height:15px;"><#2485#></th>
<td align="center">
<select name="upload_bw_min_0" class="input_option" id="upload_bw_min_0" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<select name="upload_bw_max_0" class="input_option" id="upload_bw_max_0" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<div id="upload_bw_0_desc"></div>
</td>
</tr>
<tr>
<th style="width:22%;line-height:15px;"><#2484#></th>
<td align="center">
<select name="upload_bw_min_1" class="input_option" id="upload_bw_min_1" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<select name="upload_bw_max_1" class="input_option" id="upload_bw_max_1" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<div id="upload_bw_1_desc"></div>
</td>
</tr>
<tr>
<th style="width:22%;line-height:15px;"><#2879#></th>
<td align="center">
<select name="upload_bw_min_2" class="input_option" id="upload_bw_min_2" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<select name="upload_bw_max_2" class="input_option" id="upload_bw_max_2" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<div id="upload_bw_2_desc"></div>
</td>
</tr>
<tr>
<th style="width:22%;line-height:15px;"><#2855#></th>
<td align="center">
<select name="upload_bw_min_3" class="input_option" id="upload_bw_min_3" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<select name="upload_bw_max_3" class="input_option" id="upload_bw_max_3" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<div id="upload_bw_3_desc"></div>
</td>
</tr>
<tr>
<th style="width:22%;line-height:15px;"><#2856#></th>
<td align="center">
<select name="upload_bw_min_4" class="input_option" id="upload_bw_min_4" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<select name="upload_bw_max_4" class="input_option" id="upload_bw_max_4" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<div id="upload_bw_4_desc"></div>
</td>
</tr>
</table>
</td>
<td width="42%" style="font-size:12px; border-collapse: collapse;border:0;">
<table width="100%" border="0" cellpadding="4" cellspacing="0" style="font-size:12px; border-collapse: collapse;border:0;">
<thead>
<tr>
<td colspan="3"><#1944#></td>
</tr>
<tr style="height: 55px;">
<th style="width:31%;line-height:15px;color:#FFFFFF;"><#1947#></th>
<th style="width:37%;line-height:15px;color:#FFFFFF;"><a href="javascript:void(0);" onClick="openHint(20,5);"><div class="table_text"><#2874#></div></a></th>
<th style="width:32%;line-height:15px;color:#FFFFFF;"><#1830#></th>
</tr>
</thead>
<tr>
<th style="width:31%;line-height:15px;"><#2485#></th>
<td align="center">
<select name="download_bw_max_0" class="input_option" id="download_bw_max_0" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<div id="download_bw_0_desc"></div>
</td>
</tr>
<tr>
<th style="width:31%;line-height:15px;"><#2484#></th>
<td align="center">
<select name="download_bw_max_1" class="input_option" id="download_bw_max_1" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<div id="download_bw_1_desc"></div>
</td>
</tr>
<tr>
<th style="width:31%;line-height:15px;"><#2879#></th>
<td align="center">
<select name="download_bw_max_2" class="input_option" id="download_bw_max_2" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<div id="download_bw_2_desc"></div>
</td>
</tr>
<tr>
<th style="width:31%;line-height:15px;"><#2855#></th>
<td align="center">
<select name="download_bw_max_3" class="input_option" id="download_bw_max_3" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<div id="download_bw_3_desc"></div>
</td>
</tr>
<tr>
<th style="width:31%;line-height:15px;"><#2856#></th>
<td align="center">
<select name="download_bw_max_4" class="input_option" id="download_bw_max_4" onchange="gen_options();"></select>
<span style="color:white">%</span>
</td>
<td align="center">
<div id="download_bw_4_desc"></div>
</td>
</tr>
</table>
</td>
</tr>
</table>
</td>
</tr>
</table>
</td></tr>
<tr><td>
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable" style="margin-top:8px;">
<thead>
<tr>
<td><#2486#><!-- &nbsp;&nbsp;&nbsp;&nbsp;( <#3230#> ) -->
<a id="packet_table_display_id" style="margin-left:490px;display:none;" onclick='bw_crtl_display("packet_table_display_id", "packet_table");'>-</a>
</td>
</tr>
</thead>
<tr>
<td>
<div id="packet_table">
<table width="100%" border="0" cellpadding="4" cellspacing="0">
<tr><td colspan="5" style="font-size:12px; border-collapse: collapse;border:0;">
<span><#3230#></span>
</td>
</tr>
<tr>
<td style="font-size:12px; border-collapse: collapse;border:0;">
<input type="checkbox" name="qos_ack_checkbox" <% nvram_match("qos_ack", "on", "checked"); %>>ACK
<input type="hidden" name="qos_ack">
</td>
<td style="font-size:12px; border-collapse: collapse;border:0;">
<input type="checkbox" name="qos_syn_checkbox" <% nvram_match("qos_syn", "on", "checked"); %>>SYN
<input type="hidden" name="qos_syn">
</td>
<td style="font-size:12px; border-collapse: collapse;border:0;">
<input type="checkbox" name="qos_fin_checkbox" <% nvram_match("qos_fin", "on", "checked"); %>>FIN
<input type="hidden" name="qos_fin">
</td>
<td style="font-size:12px; border-collapse: collapse;border:0;">
<input type="checkbox" name="qos_rst_checkbox" <% nvram_match("qos_rst", "on", "checked"); %>>RST
<input type="hidden" name="qos_rst">
</td>
<td style="font-size:12px; border-collapse: collapse;border:0;">
<input type="checkbox" name="qos_icmp_checkbox" <% nvram_match("qos_icmp", "on", "checked"); %>>ICMP
<input type="hidden" name="qos_icmp">
</td>
</tr>
</table>
</div>
</td>
</tr>
</table>
</td></tr>
<tr><td>
<div class="apply_gen">
<input name="button" type="button" class="button_gen" onClick="applyRule()" value="<#287#>"/>
</div>
</td></tr>
<tr><td>
<div id="manual_BW_setting" style="display:none;">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
<thead>
<tr>
<td colspan="2"><#1650#></td>
</tr>
</thead>
<tr>
<th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(20, 2);"><#3726#></a></th>
<td>
<input type="text" maxlength="10" id="qos_obw" name="qos_obw" onKeyPress="return validator.isNumber(this,event);" class="input_15_table" value="<% nvram_get("qos_obw"); %>" onblur="gen_options();" autocorrect="off" autocapitalize="off">
<select id="qos_obw_scale" class="input_option" style="width:87px;" onChange="changeScale('qos_obw');">
<option value="Kb/s">Kb/s</option>
<option value="Mb/s">Mb/s</option>
</select>
</td>
</tr>
<tr>
<th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(20, 2);"><#1944#></a></th>
<td>
<input type="text" maxlength="10" id="qos_ibw" name="qos_ibw" onKeyPress="return validator.isNumber(this,event);" class="input_15_table" value="<% nvram_get("qos_ibw"); %>" onblur="gen_options();" autocorrect="off" autocapitalize="off">
<select id="qos_ibw_scale" class="input_option" style="width:87px;" onChange="changeScale('qos_ibw');">
<option value="Kb/s">Kb/s</option>
<option value="Mb/s">Mb/s</option>
</select>
</td>
</tr>
</table>
</div>
</td></tr>
</table>
</td>
</tr>
</table>
</td>
</form>
</tr>
</table>
</td>
<td width="10" align="center" valign="top">&nbsp;</td>
</tr>
</table>
<div id="footer"></div>
</body>
</html>

