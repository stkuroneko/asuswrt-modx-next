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
<title><#971#> - <#513#></title>
<link rel="stylesheet" type="text/css" href="index_style.css">
<link rel="stylesheet" type="text/css" href="form_style.css">
<script language="JavaScript" type="text/javascript" src="/js/jquery.js"></script>
<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/help.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script language="JavaScript" type="text/javascript" src="/validator.js"></script>
<script>
var keyword_rulelist_array = "<% nvram_char_to_ascii("","keyword_rulelist"); %>";
var keyword_firewall_enable = "<% nvram_get("keyword_enable_x"); %>";
var faq_href = "https://nw-dlcdnet.asus.com/support/forward.html?model=&type=Faq&lang="+ui_lang+"&kw=&num=159";
function initial(){
show_menu();
show_keyword_rulelist();
$("#kwf_desc2 a").attr("href", faq_href);
}
function show_keyword_rulelist(){
var keyword_rulelist_row = decodeURIComponent(keyword_rulelist_array).split('<');
var code = "";
code +='<table width="100%" border="1" cellspacing="0" cellpadding="4" align="center" class="list_table" id="keyword_rulelist_table">';
if(keyword_rulelist_row.length == 1)
code +='<tr><td style="color:#FFCC00;"><#2618#></td>';
else{
for(var i =1; i < keyword_rulelist_row.length; i++){
code +='<tr id="row'+i+'">';
code +='<td width="80%">'+ keyword_rulelist_row[i] +'</td>'; //Url keyword
code +='<td width="20%">';
code +="<input class=\"remove_btn\" type=\"button\" onclick=\"deleteRow(this);\" value=\"\"/></td>";
}
}
code +='</tr></table>';
document.getElementById("keyword_rulelist_Block").innerHTML = code;
}
function deleteRow(r){
var i=r.parentNode.parentNode.rowIndex;
document.getElementById('keyword_rulelist_table').deleteRow(i);
var keyword_rulelist_value = "";
for(i=0; i<document.getElementById('keyword_rulelist_table').rows.length; i++){
keyword_rulelist_value += "<";
keyword_rulelist_value += document.getElementById('keyword_rulelist_table').rows[i].cells[0].innerHTML;
}
keyword_rulelist_array = keyword_rulelist_value;
if(keyword_rulelist_array == "")
show_keyword_rulelist();
}
function addRow(obj,upper){
if(validForm(obj)){
if(keyword_firewall_enable != "1")
document.form.keyword_enable_x[0].checked = true;
var rule_num = document.getElementById('keyword_rulelist_table').rows.length;
var item_num = document.getElementById('keyword_rulelist_table').rows[0].cells.length;
if(rule_num >= upper){
alert("<#2699#> " + upper + " <#2700#>");
return false;
}
for(i=0; i<rule_num; i++){
for(j=0; j<item_num-1; j++){ //only 1 value column
if(obj.value == document.getElementById('keyword_rulelist_table').rows[i].cells[j].innerHTML){
alert("<#2692#>");
return;
}
}
}
keyword_rulelist_array += "<";
keyword_rulelist_array += obj.value;
obj.value = "";
show_keyword_rulelist();
}
}
function applyRule(){
var rule_num = document.getElementById('keyword_rulelist_table').rows.length;
var item_num = document.getElementById('keyword_rulelist_table').rows[0].cells.length;
var tmp_value = "";
for(i=0; i<rule_num; i++){
tmp_value += "<"
for(j=0; j<item_num-1; j++){
tmp_value += document.getElementById('keyword_rulelist_table').rows[i].cells[j].innerHTML;
if(j != item_num-2)
tmp_value += ">";
}
}
if(tmp_value == "<"+"<#2618#>" || tmp_value == "<")
tmp_value = "";
document.form.keyword_rulelist.value = tmp_value;
showLoading();
document.form.submit();
}
function validForm(obj){
if(obj.value==""){
alert("<#420#>");
obj.focus();
obj.select();
return false;
}else if(!Block_chars(obj, ["#", "%" ,"&" ,"*" ,"{" ,"}" ,"\\" ,":" ,"<" ,">" ,"?" ,"/" ,"+"])){
return false;
}
return true;
}
function done_validating(action){
refreshpage();
}
</script>
</head>
<body onload="initial();" onunLoad="return unload_body();" class="bg">
<div id="TopBanner"></div>
<div id="Loading" class="popup_bg"></div>
<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>
<form method="post" name="form" id="ruleForm" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="current_page" value="Advanced_KeywordFilter_Content.asp">
<input type="hidden" name="next_page" value="Advanced_KeywordFilter_Content.asp">
<input type="hidden" name="modified" value="0">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_wait" value="5">
<input type="hidden" name="action_script" value="restart_firewall">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>" disabled>
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">
<input type="hidden" name="keyword_rulelist" value="<% nvram_get("keyword_rulelist"); %>">
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
<td valign="top" >
<table width="760px" border="0" cellpadding="4" cellspacing="0" class="FormTitle" id="FormTitle">
<tbody>
<tr>
<td bgcolor="#4D595D" valign="top" >
<div>&nbsp;</div>
<div class="formfonttitle"><#509#> - <#513#></div>
<div style="margin:10px 0 10px 5px;" class="splitLine"></div>
<div class="formfontdesc"><#2222#></div>
<div id="kwf_desc2" class="formfontdesc"><#2223#></div>
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
<thead>
<tr>
<td colspan="2"><#3551#></td>
</tr>
</thead>
<tr>
<th><#2221#></th>
<td>
<input type="radio" value="1" name="keyword_enable_x" <% nvram_match("keyword_enable_x", "1", "checked"); %>><#1806#>
<input type="radio" value="0" name="keyword_enable_x" <% nvram_match("keyword_enable_x", "0", "checked"); %>><#1803#>
</td>
</tr>
</table>
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable_table">
<thead>
<tr>
<td colspan="2"><#2224#>&nbsp;(<#2843#>&nbsp;64)</td>
</tr>
</thead>
<tr>
<th width="80%"><#2224#></th>
<th width="20%"><#2842#></th>
</tr>
<tr>
<td width="80%">
<input type="text" maxlength="32" class="input_32_table" name="url_keyword_x_0" onKeyPress="return validator.isString(this, event)" autocorrect="off" autocapitalize="off">
</td>
<td width="20%">
<input class="add_btn" type="button" onClick="addRow(document.form.url_keyword_x_0, 64);" value="">
</td>
</tr>
</table>
<div id="keyword_rulelist_Block"></div>
<div class="apply_gen">
<input type="button" class="button_gen" onclick="applyRule()" value="<#287#>"/>
</div>
</td>
</tr>
</tbody>
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

