# YARA_RULES
# Developing Testing Tools
	Test the first yara rules
	Producing a Static Test File:
		Create a .txt file and insert some patterns like ws3_32.dll... Take Ytest.txt as an example
		run command to check patterns matching: yara -s -m firs_yara_rules.yara Ytest.txt
					in which: -s: prints strings that matche
								-m : prints the metadata
		check patterns matching with the live process: 
			Open “Developer Command Prompt for Visual Studio”
			compile c# file to exe file: csc file_name.cs
			run exe file and get PID
			yara -s -m first_yara_rules PID
## Identifying File Types and Content
