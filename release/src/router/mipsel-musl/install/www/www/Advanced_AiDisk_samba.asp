<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title><#971#> - <#505#></title>
<link rel="stylesheet" type="text/css" href="/index_style.css">
<link rel="stylesheet" type="text/css" href="/form_style.css">
<link rel="stylesheet" type="text/css" href="/aidisk/AiDisk_style.css">
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/validator.js"></script>
<script type="text/javascript" src="/disk_functions.js"></script>
<script type="text/javascript" src="/js/jquery.js"></script>
<script type="text/javascript" src="/js/httpApi.js"></script>
<script type="text/javascript" src="/switcherplugin/jquery.iphone-switch.js"></script>
<style>
.charToUpperCase{
text-transform: uppercase;
}
</style>
<script type="text/javascript">
<% get_AiDisk_status(); %>
<% get_permissions_of_account(); %>
<% get_permissions_of_group(); %>
var lan_hostname = "<% nvram_get("lan_hostname"); %>";
var lan_domain = "<% nvram_get("lan_domain"); %>".split('.')[0];
var PROTOCOL = "cifs";
var NN_status = get_cifs_status(); // Network-Neighborhood
var FTP_status = get_ftp_status(); // FTP
var AM_to_cifs = get_share_management_status("cifs"); // Account Management for Network-Neighborhood
var AM_to_ftp = get_share_management_status("ftp"); // Account Management for FTP
var accounts = [<% get_all_accounts(); %>][0];
var groups = [<% get_all_groups(); %>];
var lastClickedAccount = 0;
var selectedAccount = null;
var select_flag = "account";
if(pm_support)
select_flag = "group";
var changedPermissions = new Array();
var folderlist = new Array();
var faq_href = "https://nw-dlcdnet.asus.com/support/forward.html?model=&type=Faq&lang="+ui_lang+"&kw=&num=103";
function initial(){
if(re_mode == "1"){
$("#apply_btn").addClass("perNode_apply_gen");
show_loading_obj();
}
else{
console.log("else");
$("#content_table").addClass("content");
$("#FormTitle").addClass("FormTitle content_bg");
$("#apply_btn").addClass("apply_gen");
show_menu();
}
$("#FormTitle").css("display", "");
document.aidiskForm.protocol.value = PROTOCOL;
var sambainfo = httpApi.hookGet("get_SambaInfo");
if(sambainfo != undefined && sambainfo != ""){
var vernums = sambainfo.replace("Version", "").trim().split(".");
if(parseInt(vernums[0]) >= 3 && parseInt(vernums[1]) >= 6){
$("#smbv1_hint").remove();
}
}
if($("#smbv1_hint").length > 0){
document.getElementById('SMBv1_FAQ').target="_blank";
document.getElementById('SMBv1_FAQ').style.textDecoration="underline";
document.getElementById("SMBv1_FAQ").href=faq_href;
}
if(is_KR_sku){
document.getElementById("radio_anonymous_enable_tr").style.display = "none";
}
if(!WebDav_support)
document.getElementById("clouddiskstr").style.display = "none";
if (!ntfs_sparse_support)
document.getElementById('ntfs_sparse_files').style.display = "none";
else
document.getElementById('ntfs_sparse_files').style.display = "";
showAccountGroupMenu(select_flag);
showPermissionTitle();
document.getElementById("computer_name").placeholder = lan_hostname.toUpperCase();
document.getElementById("st_samba_workgroup").placeholder = lan_domain.toUpperCase();
setTimeout('get_disk_tree();', 1000);
onEvent();
if(!hadPlugged('storage')){
}
if(based_modelid == "BRT-AC828") {
document.getElementById("returnBtn").style.display = "none";
}
if(pm_support)
$("#trPMGroup").css("display", "block");
else
$("#trAccount").css("display", "block");
if(get_manage_type(PROTOCOL)){
document.getElementById("loginMethod").innerHTML = "<#1102#>";
document.getElementById("accountMask").style.display = "none";
}
else{
document.getElementById("loginMethod").innerHTML = "<#1101#>";
document.getElementById("accountMask").style.display = "block";
$("#accountMask").css("height", ($("#shareStatus").height() + $(".AiDiskTable").height()));
}
}
function get_disk_tree(){
if(this.isLoading == 0){
get_layer_items("0", "gettree");
setTimeout('get_disk_tree();', 1000);
}
else
;
}
function get_accounts(){
return this.accounts;
}
function switchAppStatus(protocol){ // turn on/off the share
var status;
var confirm_str_on, confirm_str_off;
if(protocol == "cifs"){
status = this.NN_status;
confirm_str_off= "<#1763#>"; //"<#1765#>"+ By Viz 2011.09
confirm_str_on = "<#1767#>";
}
else if(protocol == "ftp"){
status = this.FTP_status;
confirm_str_off = "<#1764#>";
confirm_str_on = "<#1768#>";
}
switch(status){
case 1:
if(confirm(confirm_str_off)){
showLoading();
document.aidiskForm.action = "/aidisk/switch_AiDisk_app.asp";
document.aidiskForm.protocol.value = protocol;
document.aidiskForm.flag.value = "off";
document.aidiskForm.submit();
}
else{
refreshpage();
}
break;
case 0:
if(confirm(confirm_str_on)){
showLoading();
document.aidiskForm.action = "/aidisk/switch_AiDisk_app.asp";
document.aidiskForm.protocol.value = protocol;
document.aidiskForm.flag.value = "on";
document.aidiskForm.submit();
}
else{
refreshpage();
}
break;
}
}
function resultOfSwitchAppStatus(){
refreshpage(1);
}
function switchAccount(protocol){
if(protocol != "cifs" && protocol != "ftp")
return;
switch(get_manage_type(protocol)){
case 1:
if(confirm("<#1103#>")){
document.aidiskForm.action = "/aidisk/switch_share_mode.asp";
document.aidiskForm.protocol.value = protocol;
document.aidiskForm.mode.value = "share";
showLoading();
document.aidiskForm.submit();
}
else{
refreshpage();
}
break;
case 0:
document.aidiskForm.action = "/aidisk/switch_share_mode.asp";
document.aidiskForm.protocol.value = protocol;
document.aidiskForm.mode.value = "account";
showLoading();
document.aidiskForm.submit();
break;
}
}
function resultOfSwitchShareMode(){
refreshpage();
}
function showAccountGroupMenu(flag){
var account_group_menu_code = "";
if(flag == "group")
account_group_list = this.groups;
else
account_group_list = this.accounts;
if(account_group_list.length <= 0)
account_group_menu_code += '<div class="noAccount" id="noAccount"><#3066#></div>\n'
else{
for(var i = 0; i < account_group_list.length; ++i){
account_group_menu_code += '<div class="userIcon" id="';
account_group_menu_code += "account"+i;
if(decodeURIComponent(this.accounts[i]).length > 18){
account_group_menu_code += '" onClick="setSelectAccount('+i+');" style="white-space:nowrap;font-family:Courier New, Courier, mono;" title="'+htmlEnDeCode.htmlEncode(decodeURIComponent(account_group_list[i]))+'">'
account_group_menu_code += htmlEnDeCode.htmlEncode(decodeURIComponent(account_group_list[i])).substring(0,15) + '...';
}
else{
account_group_menu_code += '" onClick="setSelectAccount('+i+');" style="white-space:nowrap;font-family:Courier New, Courier, mono;">'
account_group_menu_code += htmlEnDeCode.htmlDecode(decodeURIComponent(decodeURIComponent(account_group_list[i])));
}
account_group_menu_code += '</div>\n';
}
}
document.getElementById("account_menu").innerHTML = account_group_menu_code;
if(this.accounts.length > 0){
if(get_manage_type(PROTOCOL) == 1)
setSelectAccount(0);
}
}
function showPermissionTitle(){
var code = "";
code += '<table width="190"><tr>';
if(PROTOCOL == "cifs"){
code += '<td width="34%" align="center">R/W</td>';
code += '<td width="28%" align="center">R</td>';
code += '<td width="38%" align="center"><#277#></td>';
}else if(PROTOCOL == "ftp"){
code += '<td width="28%" align="center">R/W</td>';
code += '<td width="22%" align="center">W</td>';
code += '<td width="22%" align="center">R</td>';
code += '<td width="28%" align="center"><#277#></td>';
}
code += '</tr></table>';
document.getElementById("permissionTitle").innerHTML = code;
}
var controlApplyBtn = 0;
function showApplyBtn(){
if(this.controlApplyBtn == 1){
document.getElementById("changePermissionBtn").className = "button_gen";
document.getElementById("changePermissionBtn").disabled = false;
}else{
document.getElementById("changePermissionBtn").className = "button_gen_dis";
document.getElementById("changePermissionBtn").disabled = true;
}
}
function setSelectAccount(account_order){
if(select_flag == "group")
this.selectedAccount = groups[account_order];
else
this.selectedAccount = accounts[account_order];
onEvent();
show_permissions_of_account(account_order, PROTOCOL);
contrastSelectAccount(account_order);
}
function getSelectedAccount(){
return this.selectedAccount;
}
function show_permissions_of_account(account_order, protocol){
if(select_flag == "group"){
var accountName = groups[account_order];
}
else{
var accountName = accounts[account_order];
}
var poolName;
var permissions;
try{
for(var i=0; i < usbDevicesList.length; i++){
for(var j=0; j < usbDevicesList[i].partition.length; j++){
poolName = usbDevicesList[i].partition[j].mountPoint;
if(!this.clickedFolderBarCode[poolName])
continue;
if(select_flag == "group"){
permissions = get_group_permissions_in_pool(accountName, poolName);
}
else{
permissions = get_account_permissions_in_pool(accountName, poolName);
}
for(var j = 1; j < permissions.length; ++j){
var folderBarCode = get_folderBarCode_in_pool(poolName, permissions[j][0]);
if(protocol == "cifs")
showPermissionRadio(folderBarCode, permissions[j][1]);
else if(protocol == "ftp")
showPermissionRadio(folderBarCode, permissions[j][2]);
else{
alert("Wrong protocol when get permission!"); // system error msg. must not be translate
return;
}
}
}
}
}
catch(err){
return true;
}
}
function get_permission_of_folder(accountName, poolName, folderName, protocol){
if(select_flag == "group"){
var permissions = get_group_permissions_in_pool(accountName, poolName);
}
else{
var permissions = get_account_permissions_in_pool(accountName, poolName);
}
for(var i = 1; i < permissions.length; ++i)
if(permissions[i][0] == folderName){
if(protocol == "cifs")
return permissions[i][1];
else if(protocol == "ftp")
return permissions[i][2];
else{
alert("Wrong protocol when get permission!"); // system error msg. must not be translate
return;
}
}
alert("Wrong folderName when get permission!"); // system error msg. must not be translate
}
function contrastSelectAccount(account_order){
if(this.lastClickedAccount != 0){
this.lastClickedAccount.className = "userIcon";
}
var selectedObj = document.getElementById("account"+account_order);
selectedObj.className = "userIcon_click";
this.lastClickedAccount = selectedObj;
}
function submitChangePermission(protocol){
var orig_permission;
var target_account = null;
var target_folder = null;
var target_account_group = null;
if(select_flag == "group")
target_account_group = groups;
else
target_account_group = accounts;
for(var i = -1; i < target_account_group.length; ++i){
if(i == -1)
target_account = "guest";
else
target_account = target_account_group[i];
if(!changedPermissions[target_account])
continue;
var usbPartitionMountPoint = "";
for(var j=0; j < usbDevicesList.length; j++){
for(var k=0; k < usbDevicesList[j].partition.length; k++){
usbPartitionMountPoint = usbDevicesList[j].partition[k].mountPoint;
if(!changedPermissions[target_account][usbPartitionMountPoint])
continue;
folderlist = get_sharedfolder_in_pool(usbPartitionMountPoint);
for(var k = 0; k < folderlist.length; ++k){
target_folder = folderlist[k];
if(!changedPermissions[target_account][usbPartitionMountPoint][target_folder])
continue;
if(target_account == "guest")
orig_permission = get_permission_of_folder(null, usbPartitionMountPoint, target_folder, PROTOCOL);
else
orig_permission = get_permission_of_folder(target_account, usbPartitionMountPoint, target_folder, PROTOCOL);
if(changedPermissions[target_account][usbPartitionMountPoint][target_folder] == orig_permission)
continue;
if(changedPermissions[target_account][usbPartitionMountPoint][target_folder] == -1)
continue;
if(select_flag == "group")
document.aidiskForm.action = "/aidisk/set_group_permission.asp";
else
document.aidiskForm.action = "/aidisk/set_account_permission.asp";
if(target_account == "guest")
document.getElementById("account").disabled = 1;
else{
document.getElementById("account").disabled = 0;
document.getElementById("account").value = target_account;
}
document.getElementById("pool").value = usbPartitionMountPoint;
if(target_folder == "")
document.getElementById("folder").disabled = 1;
else{
document.getElementById("folder").disabled = 0;
document.getElementById("folder").value = target_folder;
}
document.getElementById("protocol").value = protocol;
document.getElementById("permission").value = this.changedPermissions[target_account][usbPartitionMountPoint][target_folder];
changedPermissions[target_account][usbPartitionMountPoint][target_folder] = -1;
showLoading();
document.aidiskForm.submit();
return;
}
}
}
}
refreshpage();
}
function changeActionButton(selectedObj, type, action, flag){
if(type == "User")
if(this.accounts.length <= 0)
if(action == "Del" || action == "Mod")
return;
if(typeof(flag) == "number"){
if(flag == 0)
selectedObj.className = selectedObj.id + '_add';
else
selectedObj.className = selectedObj.id + '_hover';
}
else{
selectedObj.className = selectedObj.id;
}
}
function resultOfCreateAccount(){
refreshpage();
}
function onEvent(){
if(1){
changeActionButton(document.getElementById("createAccountBtn"), 'User', 'Add', 0);
var accounts_length = this.accounts.length;
var maximum_account = httpApi.nvramGet(["st_max_user"]).st_max_user;
document.getElementById("createAccountBtn").onclick = function(){
if(accounts_length >= maximum_account) {
alert("<#2699#> " + maximum_account + " <#2700#>");
return false;
}
else
popupWindow('OverlayMask','/aidisk/popCreateAccount.asp');
};
document.getElementById("createAccountBtn").onmouseover = function(){
changeActionButton(this, 'User', 'Add', 1);
};
document.getElementById("createAccountBtn").onmouseout = function(){
changeActionButton(this, 'User', 'Add', 0);
};
}
else{
changeActionButton(document.getElementById("createAccountBtn"), 'User', 'Add');
document.getElementById("createAccountBtn").onclick = function(){};
document.getElementById("createAccountBtn").onmouseover = function(){};
document.getElementById("createAccountBtn").onmouseout = function(){};
document.getElementById("createAccountBtn").title = (accounts.length < 6)?"<#1040#>":"<#1006#>";
}
if(this.accounts.length > 0 && this.selectedAccount != null && this.selectedAccount.length > 0 && this.accounts[0] != this.selectedAccount){
changeActionButton(document.getElementById("modifyAccountBtn"), 'User', 'Mod', 0);
document.getElementById("modifyAccountBtn").onclick = function(){
if(!selectedAccount){
alert("<#1113#>");
return;
}
popupWindow('OverlayMask','/aidisk/popModifyAccount.asp');
};
document.getElementById("modifyAccountBtn").onmouseover = function(){
changeActionButton(this, 'User', 'Mod', 1);
};
document.getElementById("modifyAccountBtn").onmouseout = function(){
changeActionButton(this, 'User', 'Mod', 0);
};
}
else{
changeActionButton(document.getElementById("modifyAccountBtn"), 'User', 'Mod');
document.getElementById("modifyAccountBtn").onclick = function(){};
document.getElementById("modifyAccountBtn").onmouseover = function(){};
document.getElementById("modifyAccountBtn").onmouseout = function(){};
}
if(this.accounts.length > 1 && this.selectedAccount != null && this.selectedAccount.length > 0 && this.accounts[0] != this.selectedAccount){
changeActionButton(document.getElementById("deleteAccountBtn"), 'User', 'Del', 0);
document.getElementById("deleteAccountBtn").onclick = function(){
if(!selectedAccount){
alert("<#1113#>");
return;
}
popupWindow('OverlayMask','/aidisk/popDeleteAccount.asp');
};
document.getElementById("deleteAccountBtn").onmouseover = function(){
changeActionButton(this, 'User', 'Del', 1);
};
document.getElementById("deleteAccountBtn").onmouseout = function(){
changeActionButton(this, 'User', 'Del', 0);
};
}
else{
changeActionButton(document.getElementById("deleteAccountBtn"), 'User', 'Del');
document.getElementById("deleteAccountBtn").onclick = function(){};
document.getElementById("deleteAccountBtn").onmouseover = function(){};
document.getElementById("deleteAccountBtn").onmouseout = function(){};
}
if(this.selectedPoolOrder >= 0 && this.selectedFolderOrder < 0){
changeActionButton(document.getElementById("createFolderBtn"), 'Folder', 'Add', 0);
document.getElementById("createFolderBtn").onclick = function(){
if(selectedDiskOrder < 0){
alert("<#1114#>");
return;
}
if(selectedPoolOrder < 0){
alert("<#1116#>");
return;
}
popupWindow('OverlayMask','/aidisk/popCreateFolder.asp');
};
document.getElementById("createFolderBtn").onmouseover = function(){
changeActionButton(this, 'Folder', 'Add', 1);
};
document.getElementById("createFolderBtn").onmouseout = function(){
changeActionButton(this, 'Folder', 'Add', 0);
};
}
else{
changeActionButton(document.getElementById("createFolderBtn"), 'Folder', 'Add');
document.getElementById("createFolderBtn").onclick = function(){};
document.getElementById("createFolderBtn").onmouseover = function(){};
document.getElementById("createFolderBtn").onmouseout = function(){};
}
if(this.selectedFolderOrder >= 0){
changeActionButton(document.getElementById("deleteFolderBtn"), 'Folder', 'Del', 0);
changeActionButton(document.getElementById("modifyFolderBtn"), 'Folder', 'Mod', 0);
document.getElementById("deleteFolderBtn").onclick = function(){
if(selectedFolderOrder < 0){
alert("<#1115#>");
return;
}
popupWindow('OverlayMask','/aidisk/popDeleteFolder.asp');
};
document.getElementById("deleteFolderBtn").onmouseover = function(){
changeActionButton(this, 'Folder', 'Del', 1);
};
document.getElementById("deleteFolderBtn").onmouseout = function(){
changeActionButton(this, 'Folder', 'Del', 0);
};
document.getElementById("modifyFolderBtn").onclick = function(){
if(selectedFolderOrder < 0){
alert("<#1115#>");
return;
}
popupWindow('OverlayMask','/aidisk/popModifyFolder.asp');
};
document.getElementById("modifyFolderBtn").onmouseover = function(){
changeActionButton(this, 'Folder', 'Mod', 1);
};
document.getElementById("modifyFolderBtn").onmouseout = function(){
changeActionButton(this, 'Folder', 'Mod', 0);
};
}
else{
changeActionButton(document.getElementById("deleteFolderBtn"), 'Folder', 'Del');
changeActionButton(document.getElementById("modifyFolderBtn"), 'Folder', 'Mod');
document.getElementById("deleteFolderBtn").onclick = function(){};
document.getElementById("deleteFolderBtn").onmouseover = function(){};
document.getElementById("deleteFolderBtn").onmouseout = function(){};
document.getElementById("modifyFolderBtn").onclick = function(){};
document.getElementById("modifyFolderBtn").onmouseover = function(){};
document.getElementById("modifyFolderBtn").onmouseout = function(){};
}
document.getElementById("changePermissionBtn").onclick = function(){
submitChangePermission(PROTOCOL);
};
}
function unload_body(){
document.getElementById("createAccountBtn").onclick = function(){};
document.getElementById("createAccountBtn").onmouseover = function(){};
document.getElementById("createAccountBtn").onmouseout = function(){};
document.getElementById("deleteAccountBtn").onclick = function(){};
document.getElementById("deleteAccountBtn").onmouseover = function(){};
document.getElementById("deleteAccountBtn").onmouseout = function(){};
document.getElementById("modifyAccountBtn").onclick = function(){};
document.getElementById("modifyAccountBtn").onmouseover = function(){};
document.getElementById("modifyAccountBtn").onmouseout = function(){};
document.getElementById("createFolderBtn").onclick = function(){};
document.getElementById("createFolderBtn").onmouseover = function(){};
document.getElementById("createFolderBtn").onmouseout = function(){};
document.getElementById("deleteFolderBtn").onclick = function(){};
document.getElementById("deleteFolderBtn").onmouseover = function(){};
document.getElementById("deleteFolderBtn").onmouseout = function(){};
document.getElementById("modifyFolderBtn").onclick = function(){};
document.getElementById("modifyFolderBtn").onmouseover = function(){};
document.getElementById("modifyFolderBtn").onmouseout = function(){};
}
var reboot_confirm=0;
function applyRule(){
if(validForm()){
if(ntfs_sparse_support){
if(document.form.usb_fs_ntfs_sparse.value != "<% nvram_get("usb_fs_ntfs_sparse"); %>"){
reboot_confirm=1;
}
}
if(reboot_confirm==1){
if(confirm("<#65#>")){
FormActions("start_apply.htm", "apply", "reboot", "<% get_default_reboot_time(); %>");
showLoading();
document.form.submit();
}
}
else{
showLoading();
document.form.submit();
}
}
}
function validForm(){
if(document.form.computer_name.value.length > 0){
var alert_str = validator.samba_name(document.form.computer_name);
if(alert_str != ""){
showtext(document.getElementById("alert_msg1"), alert_str);
document.getElementById("alert_msg1").style.display = "";
document.form.computer_name.focus();
document.form.computer_name.select();
return false;
}
else
document.getElementById("alert_msg1").style.display = "none";
document.form.computer_name.value = trim(document.form.computer_name.value).toUpperCase();
}
if(document.form.st_samba_workgroup.value.length == 0 && !lan_domain){
alert("<#420#>");
document.form.st_samba_workgroup.focus();
document.form.st_samba_workgroup.select();
return false;
}
else if(document.form.st_samba_workgroup.value.length > 0){
var alert_str = validator.samba_name(document.form.st_samba_workgroup);
if(alert_str != ""){
alert(alert_str);
document.form.st_samba_workgroup.focus();
document.form.st_samba_workgroup.select();
return false;
}
document.form.st_samba_workgroup.value = trim(document.form.st_samba_workgroup.value).toUpperCase();
}
if(!validator.range(document.form.st_max_user, 1, 99)){
document.form.st_max_user.focus();
document.form.st_max_user.select();
return false;
}
return true;
}
function switchUserType(flag){
if(flag == "group")
select_flag = "group";
else
select_flag = "account";
showAccountGroupMenu(flag);
list_share_or_folder = 1; // 0: share, 1: folder.
isLoading = 0;
FromObject = "0";
Items = -1;
lastClickedObj = 0;
setTimeout('get_disk_tree();', 1000);
}
</script>
</head>
<body onLoad="initial();" onunload="unload_body();" class="bg">
<div id="TopBanner"></div>
<div id="Loading" class="popup_bg"></div>
<iframe name="hidden_frame" id="hidden_frame" width="0" height="0" frameborder="0" scrolling="no"></iframe>
<form method="post" name="aidiskForm" action="" target="hidden_frame">
<input type="hidden" name="motion" id="motion" value="">
<input type="hidden" name="layer_order" id="layer_order" value="">
<input type="hidden" name="protocol" id="protocol" value="">
<input type="hidden" name="mode" id="mode" value="">
<input type="hidden" name="flag" id="flag" value="">
<input type="hidden" name="account" id="account" value="">
<input type="hidden" name="pool" id="pool" value="">
<input type="hidden" name="folder" id="folder" value="">
<input type="hidden" name="permission" id="permission" value="">
</form>
<form method="post" name="form" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_script" value="restart_ftpsamba">
<input type="hidden" name="action_wait" value="5">
<input type="hidden" name="modified" value="0">
<input type="hidden" name="current_page" value="Advanced_AiDisk_samba.asp">
<table id="content_table" border="0" align="center" cellpadding="0" cellspacing="0">
<tr>
<td width="17">&nbsp;</td>
<td valign="top" width="202">
<div id="mainMenu"></div>
<div id="subMenu"></div>
</td>
<td valign="top">
<div id="tabMenu" class="submenuBlock"></div>
<div id="FormTitle" align="left" border="0" cellpadding="0" cellspacing="0" style="width: 760px; display: none;">
<table border="0" cellpadding="5" cellspacing="0">
<tbody>
<tr>
<td>
<div style="width: 99%; margin-top: 30px; margin-bottom: 5px;">
<span class="formfonttitle"><#504#> - <#505#><span id="clouddiskstr"> / <#1752#></span></span>
<span id="returnBtn" class="returnBtn">
<img onclick="go_setting('/APP_Installation.asp')" align="right" title="<#484#>" src="/images/backprev.png" onMouseOver="this.src='/images/backprevclick.png'" onMouseOut="this.src='/images/backprev.png'">
</span>
</div>
<div id="splitLine" class="splitLine"></div>
<div class="formfontdesc" style="margin-top: 10px;"><#3327#></div>
<div id="smbv1_hint" class="formfontdesc"><#1050#>&nbsp;<#3328#></div>
</td>
</tr>
<tr>
<td>
<table width="99%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
<tr>
<th><#2041#></th>
<td>
<div class="left" style="width:94px; float:left; cursor:pointer;" id="radio_samba_enable"></div>
<div class="iphone_switch_container" style="height:32px; width:74px; position: relative; overflow: hidden">
<script type="text/javascript">
$('#radio_samba_enable').iphoneSwitch(NN_status,
function() {
switchAppStatus(PROTOCOL);
},
function() {
switchAppStatus(PROTOCOL);
}
);
</script>
</div>
</td>
</tr>
<tr id="radio_anonymous_enable_tr" style="height:60px;">
<th><#1097#></th>
<td>
<div class="left" style="margin-top:5px;width:94px;float:left; cursor:pointer;" id="radio_anonymous_enable"></div>
<div class="iphone_switch_container" style="display:table-cell;vertical-align:middle;height:45px;position:relative;overflow:hidden">
<script type="text/javascript">
$('#radio_anonymous_enable').iphoneSwitch(!get_manage_type(PROTOCOL),
function() {
switchAccount(PROTOCOL);
},
function() {
switchAccount(PROTOCOL);
}
);
</script>
<span id="loginMethod" style="color:#FC0"></span>
</div>
</td>
</tr>
<tr>
<th>
<a class="hintstyle" href="javascript:void(0);" onClick="openHint(17,2);"><#3394#></a>
</th>
<td>
<div><input type="text" name="computer_name" id="computer_name" class="input_20_table charToUpperCase" maxlength="15" value="<% nvram_get("computer_name"); %>" autocorrect="off" autocapitalize="on"><br/>
<span id="alert_msg1" style="color:#FC0;"></span></div>
</td>
</tr>
<tr>
<th>
<a class="hintstyle" href="javascript:void(0);" onClick="openHint(17,3);"><#3407#></a>
</th>
<td>
<input type="text" name="st_samba_workgroup" id="st_samba_workgroup" class="input_20_table charToUpperCase" maxlength="15" value="<% nvram_get("st_samba_workgroup"); %>" autocorrect="off" autocapitalize="on">
</td>
</tr>
<tr>
<th>
<a class="hintstyle" href="javascript:void(0);" onClick="openHint(17,1);"><#3402#></a>
</th>
<td>
<input type="text" name="st_max_user" class="input_3_table" maxlength="2" value="<% nvram_get("st_max_user"); %>" onKeyPress="return validator.isNumber(this, event);" autocorrect="off" autocapitalize="off">
</td>
</tr>
<tr id="ntfs_sparse_files" style="">
<th><#1099#></th>
<td>
<select name="usb_fs_ntfs_sparse" class="input_option">
<option class="content_input_fd" value="0" <% nvram_match("usb_fs_ntfs_sparse", "0","selected"); %>><#4183#></option>
<option class="content_input_fd" value="1" <% nvram_match("usb_fs_ntfs_sparse", "1","selected"); %>><#4182#></option>
</select>
</td>
</tr>
</table>
<div id="apply_btn">
<input type="button" class="button_gen" value="<#287#>" onclick="applyRule();">
</div>
<div id="shareStatus">
<div id="tableMask"></div>
<div id="accountMask"></div>
<table width="740px" height="35" cellpadding="2" cellspacing="0" class="accountBar">
<tr>
<td width="25%" style="border: 1px solid #222;">
<table align="right">
<tr id="trAccount" style="display:none;">
<td><div id="createAccountBtn" title="<#1040#>"></div></td>
<td><div id="deleteAccountBtn" title="<#1862#>"></div></td>
<td><div id="modifyAccountBtn" title="<#2995#>"></div></td>
</tr>
<tr id="trPMGroup" style="display:none;">
<td>
<select name="" id="user_type" class="input_option" onchange="switchUserType(this.value);">
<option value="group"><#3127#></option>
<option value="account"><#3129#></option>
</select>
</td>
</tr>
</table>
</td>
<td>
<table align="right">
<tr>
<td><div id="createFolderBtn" title="<#1042#>"></div></td>
<td><div id="deleteFolderBtn" title="<#1865#>"></div></td>
<td><div id="modifyFolderBtn" title="<#2999#>"></div></td>
</tr>
</table>
</td>
</tr>
</table>
</div><!-- <table width="99%" height="400" border="0" align="center" cellpadding="0" cellspacing="1" bgcolor="#999999">-->
<table width="740px" height="200" align="center" border="1" cellpadding="4" cellspacing="0" class="AiDiskTable">
<tr>
<!-- <td valign="top" bgcolor="#F8F8F8">-->
<th align="left" valign="top">
<div id="account_menu"></div>
</th>
<td valign="top">
<table width="480" border="0" cellspacing="0" cellpadding="0" class="FileStatusTitle">
<tr>
<td width="290" height="20" align="left">
<div id="machine_name" class="machineName"><#972#></div>
</td>
<td>
<div id="permissionTitle"></div>
</td>
</tr>
</table>
<div id="e0" style="font-size:10pt; margin-top:2px;"></div>
<div style="text-align:center; margin:10px auto; border-top:1px dotted #CCC; width:95%; padding:2px;">
<input name="changePermissionBtn" id="changePermissionBtn" type="button" value="<#1817#>" class="button_gen_dis" disabled="disabled">
</div>
</td>
</tr>
</table>
</td>
</tr>
</tbody>
</table>
</div>
</td>
<td width="10" align="center" valign="top">&nbsp;</td>
</tr>
</table>
</form>
<div id="footer"></div>
<div id="OverlayMask" class="popup_bg">
<div align="center">
<iframe src="" frameborder="0" scrolling="no" id="popupframe" width="400" height="400" allowtransparency="true" style="margin-top:150px;"></iframe>
</div>
<!--[if lte IE 6.5]><iframe class="hackiframe"></iframe><![endif]-->
</div>
</body>
</html>

