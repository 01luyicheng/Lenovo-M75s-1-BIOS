rem *********changes********
rem v1.0.1 - Update tool to wFlashGui
rem ************************
@echo on
IF EXIST "%programfiles(x86)%" (
	 wFlashGUIX64.exe %*
	) ELSE ( 
	 wFlashGUI.exe %*
	)
