# FHT 202 Splunk & LogScale Queries
The following queries are provided as takeaway material for the FHT 202 instructor led training. This guide includes some of the simple queries we performed in class as well as a collection of useful queries to get you started hunting in your own environment.

**Please note** these queries can be tuned to fit your environment in the following manner:
- Change use case: modify "FileName" or other parameters – many of these queries are designed to show a concept however, they can be easily modified to use in production.
- Filtering: queries can include "AND NOT" or "!=" (not equal to) statements to filter out unwanted
events
-  Change scope: searching can be done across smaller datasets by using search modifiers like:
    - Reducing the scope of the search
    - `aid=?aid`
    - `ComputerName=?ComputerName`
    - `LocalAddressIP4=?LocalAddressIP4`
- Reducing the search timeframe: you may reduce the date range of the search to reduce the total events searched

## Key Fields and Things to Remember

| Terms | Description |
| --- | --- |
| "AND" "OR" "SPACE" "(this OR that)" "This AND that" "This that" | A space in a query indicates an implied "AND" operator You can also state AND/OR depending on query logic |
| event_simpleName | Show file differences that haven't been staged |
| aid | The sensor ID. This value is unique to each installation of a Falcon sensor. When a sensor is updated or reinstalled, the host gets a new aid. In those situations, a single host could have multiple aid values over time. |
| cid | Customer ID (only one in most cases) |
| @timestamp | Timestamp of the log, this should be different than @ingestedtimestamp by LogScale | 
| ComputerName | The name of the host |
| ContextTimeStamp_decimal| The time at which an event occurredon the system, as seen by the sensor (in decimal, non-hex format). Not to be confused with timestamp which is the time the event was received by the cloud. – Applies to non-process events like DnsRequest, NetworkConnectIP4, ImageHash, AsepValueUpdate, etc. <br /> `in("#event_simpleName", values=["DnsRequest","NetworkConnectIP4","ImageHash", "AsepValueUpdate"]) \| eval(ContextTimeStamp_decimal = ContextTimeStamp * 1000) \| ContextTimeStamp_H := formatTime("%Y/%m/%d %H:%M:%S", field=ContextTimeStamp_decimal,  locale=en_US, timezone=Z)` |
| ProcessStartTime_decimal| The time the process began in UNIX epoch time (in decimal, non-hex format). Applies only to ProcessRollup2 and SyntheticProcessRollup2 <br /> `#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2\|eval(ProcessStartTime_decimal = ProcessStartTime * 1000) \| ProcessStartTime_H := formatTime("%Y/%m/%d %H:%M:%S", field=ProcessStartTime_decimal,  ocale=en_US, timezone=Z)` |
| DeviceTimeStamp_decimal| Timestamp when the event occurred on the endpoint. Applies to Device Control events |
| TargetProcessId_decimal| The unique ID of a target process (in decimal, non-hex format). This field exists in almost all events, and it represents the ID of the process that is  esponsible for the activity of the event in focus. |
| Parent_ProcessId_decimal| Field that identifies the TargetProcessId_decimal of the parent process|
| ContextProcessId_decimal| The unique ID of an event that was spawned by another process (in decimal, non-hex format) that identifies the TargetProcessId_decimal of the responsible rocess |
| RpcClientProcessId_decimal| Field in a RPC related event that identifies the TargetProcessId_decimal for the responsible process |

TODO:
## Sample Language Snippets
| # | Splunk | LogScale |
|--- | --- | --- |
| 1 | `earliest=-30d latest=now` |  |
| 2 | `\| eval ContextTimeStamp_readable=strftime (ContextTimeStamp_decimal,"%Y-%m-%d%H:%M:%S.%3f")` | `\| eval(ContextTimeStamp_decimal = ContextTimeStamp * 1000) \| ContextTimeStamp_H := formatTime("%Y/%m/%d %H:%M:%S", field=ContextTimeStamp_decimal,  locale=en_US, timezone=Z)` |
| 3 | `\| eval ProcessStartTime_readable=strftime (ProcessStartTime_decimal,"%Y-%m-%d %H:%M:%S.%3f")` | `\| eval(ProcessStartTime_decimal = ProcessStartTime * 1000) \| ProcessStartTime_H := formatTime("%Y/%m/%d %H:%M:%S", field=ProcessStartTime_decimal, locale=en_US, timezone=Z)`|
| 4 | `\| eval AEST=( ProcessStartTime_decimal + 36000) \| eval AEST_readable=strftime(AEST, "%Y-%m-%d %H:%M:%S.%3f"')` <br /> `\| eval EST=(ProcessStartTime_decimal –18000) \| eval EST_readable=strftime(EST, "%Y-%m-%d%H:%M:%S.%3f")` | `\| eval(ProcessStartTime_decimal = ProcessStartTime * 1000)` <br /> `\| eval(AEST_decimal = ProcessStartTime_decimal + 36000) \| AEST_H:= formatTime("%Y-%M-%d %H:%M:%S", field=AEST_decimal)` <br /> `\| eval(AEST_decimal = ProcessStartTime_decimal + 36000) \| AEST_H:= formatTime("%Y-%m-%d %H:%M:%S", field=AEST_decimal)` | 
| 5 | `\|search ComputerName=ComputerNameHere` | `ComputerName = “ ComputerNameHere ”` <br /> `ComputerName=?ComputerName` |
| 6 | `\| rename ComputerName AS Hostname,timestamp AS "Cloud Time"` | `rename(field=ComputerName, as=Hostname)` <br /> `"Cloud Time" := rename(timestamp)` |
| 7 | `\| sort -count` | `sort(ref_url, type=string, order=desc\|asc, limit=max)` |
| 8 | `\| join <fields>` | `join({subquery}, field=arg1, key=arg2, repo=arg3, mode=inner\|left)` |
| 9 | `\| dedup ComputerName CommandLine` | `groupBy([ComputerName, CommandLine], function=[])`|
| 10 |`\| iplocation aip` | `\| ipLocation(field=aip)` |

## Basic Process Queries from Class

|#|Splunk|LogScale|Description|
|---|---|---|---|
| 1 | `event_simpleName=ProcessRollup2 OR event_simpleName=SyntheticProcessRollup2 FileName=cmd.exe` | `"#event_simpleName"=ProcessRollup2 OR "#event_simpleName" = SyntheticProcessRollup2 \| join({#event_simpleName=AgentOnline}, field=[aid], include=[ComputerName]) \| ImageFileName=/(\/\|\\)(?<FileName>\w*\.?\w*)$/ \| FileName = cmd.exe` | Simple Process Search (modify the filename for your needs) |
| 2 | `event_simpleName=ProcessRollup2 OR event_simpleName=SyntheticProcessRollup2 FileName=cmd.exe \| table FileName ComputerName CommandLine` |  `"#event_simpleName"=ProcessRollup2 OR "#event_simpleName" = SyntheticProcessRollup2 aid=?aid \| join({#event_simpleName=AgentOnline}, field=[aid], include=[ComputerName]) \| ImageFileName=/(\/\|\\)(?<FileName>\w*\.?\w*)$/ \| FileName = cmd.exe \| table([FileName, ComputerName, CommandLine])` | Table command outputs specified fields in tabular format |
| 3 | `event_simpleName=ProcessRollup2 OR event_simpleName=SyntheticProcessRollup2 FileName=cmd.exe \| stats count by CommandLine` | `"#event_simpleName" = ProcessRollup2 OR "#event_simpleName" = SyntheticProcessRollup2 \| ImageFileName=/(\/\|\\)(?<FileName>\w*\.?\w*)$/ \| FileName = cmd.exe \| groupby(field=CommandLine, function=count())` | Stats command (e.g. count by) provides a count of events specified field(s) 

## Sub-Searching and Joins from Class
|#|Splunk|LogScale|Description|
|---|---|---|---|
| 1 | `event_simpleName=processrollup2 [search event_simpleName=processrollup2 FileName=cmd.exe \| rename ParentProcessId_decimal AS TargetProcessId_decimal \| fields aid TargetProcessId_decimal] \| stats count by FileName CommandLine` | TODO: | Show all parents of a process (e.g. cmd.exe) – Looking for how a process is launched, to see outliers|
| 2 | `event_simpleName=processrollup2 [search event_simpleName=processrollup2 FileName=cmd.exe \| rename ParentProcessId_decimal AS TargetProcessId_decimal \| fields aid TargetProcessId_decimal] \| stats count by FileName CommandLine` | `#event_simpleName=ProcessRollup2 FileName=cmd.exe \| join({#event_simpleName=AgentOnline}, field=[aid], include=[ComputerName]) \| join({#event_simpleName=UserLogon}, field=[UserSid], include=[UserName]) \| table([@timestamp, ComputerName, UserName, FileName, CommandLine])` | Show all children of a process (e.g. winlogon.exe) – Looking for typical children of a process, to see outliers | 
| 3 | `event_simpleName=ProcessRollup2 OR event_simpleName=SyntheticProcessRollup2 [search event_simpleName=DnsRequest (DomainName=*falconsplayingpoker.com OR DomainName=winteriscoming.com) \| rename ontextProcessId_decimal AS TargetProcessId_decimal \| fields aid TargetProcessId_decimal] \| table _time ComputerName UserName  ileName CommandLine` |TODO: | Show a responsible process from a "Context Process" item such as DnsRequest, NetworkConnectIP4, etc. (Edit fields as needed)
| 4 | `\| inputlookup aid_master` | Not Applicable Yet | Display the aid_master lookup table

## Other Queries from Class

|#|Splunk|LogScale|Description|
|---|---|---|---|
| 1 | `event_simpleName=DcUsbDeviceConnected \| eval CloudTime=strftime(timestamp/1000, "%Y-%m-%d %H:%M:%S.%3f")\| rename ComputerName AS Hostname, DevicePropertyClassName AS "Connection Type", DeviceManufacturer AS Manufacturer, DeviceProduct AS "Product Name",DevicePropertyDeviceDescription AS Description,DevicePropertyClassGuid_readable AS GUID, DeviceInstanceId AS "Device ID" \| stats list(CloudTime) by Hostname "Connection Type" Manufacturer "Product Name" Description GUID "Device ID"`| TODO: | USB Device Insertions with time conversion on the timestamp field, renaming of fields, and "stats list" output with the newly created CloudTime | 
| 2 | `event_simpleName=*FileWritten IsOnRemovableDisk_decimal=1\| rename DiskParentDeviceInstanceId AS DeviceInstanceId\| join aid DeviceInstanceId [search event_simpleName=DcUsbDeviceConnected]\| rename ComputerName AS Hostname, UserName AS User,DevicePropertyClassName AS "Connection Type",DeviceManufacturer AS Manufacturer, DeviceProduct AS"Product Name", DevicePropertyDeviceDescription AS Description, DeviceInstanceId AS "Device ID" \| stats list(FileName) by Hostname User "Connection Type" Manufacturer "Product Name" Description "Device ID"` | TODO: | Show files written to removable USB disk |
| 3 | `event_platform=win event_simpleName=ProcessRollup2 ImageFileName!=\\Device\\HarddiskVolume* \| fields SHA256HashData FileName aid ComputerName FilePath \| stats count(SHA256HashData) AS "Execution Count" dc(FileName) AS "File Name Variants" by aid, ComputerName, FileName, FilePath, SHA256HashData \| rename aid AS "Agent ID", ComputerName AS "Endpoint", FileName AS "File", FilePath AS Path, SHA256HashData AS SHA256`| TODO: | Show processes being run from a removable USB drive

## Joins and Sub searches
|#|Splunk|LogScale|Description|
|---|---|---|---|
| 1 | `event_simpleName=NetworkConnectIP4 NOT(RemoteAddressIP4=10.0.0.1/8 ORRemoteAddressIP4=127.0.0.1) AND NOT(RemotePort_decimal=443 OR RemotePort_decimal=80)\| rename ContextProcessId_decimal asTargetProcessId_decimal\| join TargetProcessId_decimal aid [search ProcessRollup2OR SyntheticProcessRollup2]\| stats count by ImageFileName UserName RemoteAddressIP4RemotePort_decimal \| sort + count` | TODO: | Rare external connections per user |
| 2 | `event_simpleName=NetworkConnectIP4 RemotePort_decimal IN(137, 139, 389, 3389, 445)\| rename ContextProcessId_decimal asTargetProcessId_decimal\| join TargetProcessId_decimal aid [search ProcessRollup2OR SyntheticProcessRollup2]\| stats count by ImageFileName UserName RemoteAddressIP4RemotePort_decimal\| sort – count` | TODO: | Rare internal connections (common ports) |




## Hunting Related Stacking Queries


|#|Splunk|LogScale|Description|
|---|---|---|---|
| 1 | `event_simpleName=ProcessRollup2 (FileName=mshta.exe ANDCommandLine="*script*") OR (FileName=regsrv32.exe ANDCommandLine="*\/i*") OR (FileName=msbuild.exe AND NOTCommandLine="*proj*" AND NOT CommandLine="*nodemode:1*" )OR (FileName=certutil.exe AND CommandLine="*-urlcache*")OR (FileName=wmic.exe AND CommandLine="*http*")\| table _time ComputerName FileName CommandLine` |  TODO: | Common code download and execute techniques |
| 2 | `event_simpleName=ProcessRollup2 (FileName=net.exeCommandLine IN ("*view*", "*session*")) OR FileName IN(nmap.exe, nc.exe, ncat.exe) OR (FileName=dir.exeCommandLine="*\\\\*") OR (FileName=wmic.exeCommandLine="*//node*")\| table _time ComputerName FileName CommandLine` | TODO: | Common recon binaries |
| 3 | `ComputerName=ComputerNameHereevent_simpleName=ProcessRollup2 FileName IN (ftp.exe,sftp.exe, ssh.exe, scp.exe, bitsadmin.exe) OR(FileName=copy.exe CommandLine="*\\\\*") OR(FileName=zip.exe CommandLine="*\\temp\\*") OR(FileName=7z.exe CommandLine="*\\temp\\*") OR(FileName=rar.exe CommandLine="*\\temp\\*") OR(FileName=makecab.exe CommandLine="*\\temp\\*")\| table _time ComputerName FileName CommandLine` | TODO: | Common data transfer / staging binaries
| 4 | `(event_simpleName=SuspiciousDnsRequest) OR(event_simpleName=DnsRequest DomainName IN (*.cc,falconsplayingpoker.com, *.top, *.xyz, *.pw, *.stream,*.loan, *.download, *.click, *.science, *.today,*.accountant, *.gdn, *sytes.net, *zapto.org, *hopto.org,*dynu.com, *redirectme.net, *servehttp.com,*serveftp.com, *servegame.com, *jkub.com, *itemdb.com)) \|table _time ComputerName event_simpleName DomainName`| TODO: |Suspicious DNS requests with additional domains added |


## Additional Queries

|#|Splunk|LogScale|Description|
|---|---|---|---|
| 1 | `event_simpleName=NetworkConnectIP4 NOT(RemoteAddressIP4=10.0.0.1/8 ORRemoteAddressIP4=172.16.0.0/12 ORRemoteAddressIP4=192.168.0.0/16 ORRemoteAddressIP4=127.0.0.1 ORRemoteAddressIP4=169.254.0.0/16)\| iplocation RemoteAddressIP4\| table RemoteAddressIP4 ComputerName City Region Countrylat lon`  | TODO:  |Shows geographic location information based of destination IP for external network connection|
| 2 |  `event_simpleName=ProcessRollup2 ("Teamviewer" OR"ScreenConnect" OR "Ammy" OR "LogMeIn" OR "Powershell")\| stats values(FileName) AS Parent, values(CommandLine)AS ParentCmd by ComputerName TargetProcessId_decimal\| join aid TargetProcessId_decimal [search ProcessRollup2\| stats values(CommandLine) AS ChildCommand,values(FilePath) AS ChildPath, values(FileName) ASFileName by ComputerName ParentProcessId_decimal \| renameParentProcessId_decimal AS TargetProcessId_decimal]`  | TODO:  | Processes spawning under commercial remote admin tools|
| 3 | `event_simpleName=ProcessRollup2 FileName IN(psexecsvc.exe, wsmprovhost.exe)\| stats values(FileName) AS Parent, values(CommandLine)AS ParentCmd by ComputerName TargetProcessId_decimal\| join aid TargetProcessId_decimal [search ProcessRollup2\| stats values(FileName) AS FileName, values(CommandLine)AS ChildCommand, values(FilePath) AS ChildPath byComputerName ParentProcessId_decimal \| renameParentProcessId_decimal AS TargetProcessId_decimal] ` | TODO: | Processes spawning under PsExec or PowerShell remoting  |
| 4 | `event_simpleName=ImageHashFileName="System.Management.Automation.ni.dll"\| rename FileName AS DllLoaded, ContextProcessId_decimalas TargetProcessId_decimal\| join TargetProcessId_decimal aid [search(ProcessRollup2 OR SyntheticProcessRollup2) AND NOTFileName=powershell.exe]\| stats count by CommandLine UserName DllLoaded\| sort –count` | TODO: | PowerShell DLL Loads non-PowerShell process | 
