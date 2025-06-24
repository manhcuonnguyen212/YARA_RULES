
/*
    network rules
*/
rule network_rules{

    meta:
        author="Nguyen Dang Manh Cuong"
        desciption="The first yara rule about network"
        version="1.0"
    strings:
        $f1="ws2_32.dll" nocase
        $f2="wsock32.dll" fullword
        $s1="sendto" nocase
        $s2="recvfrom" nocase
        $s3="wsastartup" nocase fullword
    condition:
        all of them
}