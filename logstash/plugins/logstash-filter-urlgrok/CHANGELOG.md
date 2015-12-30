## 1.1.1
 - Catch if the input message is nil, updated logging level to error rather than info 
## 1.1.0
 - Reversed the logic of the input filter so that any inputs defined will be blocked 
## 1.0.4
 - By default the tag_prefix has been set to nil has to be defined in the filter config if you would like to debug events
## 1.0.3
 - Fixed bug that add blank category if the segemnet was null
## 1.0.2
 - Added functionality to define multiple tags for the category tags
## 1.0.1
 - Added filter to remove http://<ip address> from the request information. Also added test to check if we have actaul request data
## 1.0.0
 - initial version of urlgrok plugin
