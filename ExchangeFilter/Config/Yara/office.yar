import "pe"
import "hash"


private rule RTFFILE {
   meta:
      description = "Detects RTF files"
   condition:
      uint32be(0) == 0x7B5C7274
}


rule CVE_2012_0158_KeyBoy  : exploit {
  meta:
      author = "Etienne Maynier <etienne@citizenlab.ca>"
      description = "CVE-2012-0158 variant"
      file = "8307e444cad98b1b59568ad2eba5f201"

  strings:
      $a = "d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff09000600000000000000000000000100000001" nocase // OLE header
      $b = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" nocase // junk data
      $c = /5(\{\\b0\}|)[ ]*2006F00(\{\\b0\}|)[ ]*6F007(\{\\b0\}|)[ ]*400200045(\{\\b0\}|)[ ]*006(\{\\b0\}|)[ ]*E007(\{\\b0\}|)[ ]*400720079/ nocase
      $d = "MSComctlLib.ListViewCtrl.2"
      $e = "ac38c874503c307405347aaaebf2ac2c31ebf6e8e3" nocase //decoding shellcode


  condition:
      all of them
}

rule potential_CVE_2017_11882  : exploit {
    meta:
      author = "ReversingLabs"
      reference = "https://www.reversinglabs.com/newsroom/news/reversinglabs-yara-rule-detects-cobalt-strike-payload-exploiting-cve-2017-11882.html"
      
    strings:
        $docfilemagic = { D0 CF 11 E0 A1 B1 1A E1 }

        $equation1 = "Equation Native" wide ascii
        $equation2 = "Microsoft Equation 3.0" wide ascii

        $mshta = "mshta" nocase
        $http  = "http://" nocase
        $https = "https://" nocase
        $cmd   = "cmd" nocase
        $pwsh  = "powershell" nocase
        $exe   = ".exe" nocase

        $address = { 12 0C 43 00 }

    condition:
        $docfilemagic at 0 and any of ($mshta, $http, $https, $cmd, $pwsh, $exe) and any of ($equation1, $equation2) and $address
}

// same as above but for RTF documents
rule rtf_cve2017_11882 : exploit {
    meta:
        author = "John Davison"
        description = "Attempts to identify the exploit CVE 2017 11882"
        reference = "https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about"
        sample = "51cf2a6c0c1a29abca9fd13cb22421da"
        score = 60
        //file_ext = "rtf"
    strings:
        $headers = { 31 63 30 30 30 30 30 30  30 32 30 30 ?? ?? ?? ??
                     61 39 30 30 30 30 30 30  ?? ?? ?? ?? ?? ?? ?? ??
                     ?? ?? ?? ?? ?? ?? ?? ??  ?? ?? ?? ?? ?? ?? ?? ??
                     ?? ?? ?? ?? ?? ?? ?? ??  30 33 30 31 30 31 30 33
                     ?? ?? }
        $font = { 30 61 30 31 30 38 35 61  35 61 }
        $winexec = { 31 32 30 63 34 33 30 30 }
    condition:
        all of them and @font > @headers and @winexec == @font + ((5 + 44) * 2)
}


rule Maldoc_Suspicious_OLE_target :maldoc {
  meta:
    description =  "Detects maldoc With Tartgeting Suspicuios OLE"
    author = "Donguk Seo"
    reference = "https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/"
    filetype = "Office documents"
    date = "2018-06-13"
  strings:
    $env1 = /oleObject".*Target=.*.http.*.doc"/
    $env2 = /oleObject".*Target=.*.http.*.ppt"/
    $env3 = /oleObject".*Target=.*.http.*.xlx"/
  condition:
    any of them
}



rule maldoc_API_hashing : maldoc {
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {AC 84 C0 74 07 C1 CF 0D 01 C7 EB F4 81 FF}
        $a2 = {AC 84 C0 74 07 C1 CF 07 01 C7 EB F4 81 FF}
    condition:
        any of them
}

rule maldoc_indirect_function_call_1 : maldoc {
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF 75 ?? FF 55 ??}
    condition:
        for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))
}

rule maldoc_indirect_function_call_2 : maldoc {
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF B5 [4] FF 95 [3] ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 2) == uint8(@a[i] + 8)) and (uint8(@a[i] + 3) == uint8(@a[i] + 9)) and (uint8(@a[i] + 4) == uint8(@a[i] + 10)) and (uint8(@a[i] + 5) == uint8(@a[i] + 11)))
}

rule maldoc_indirect_function_call_3 : maldoc {
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF B7 [4] FF 57 ??}
    condition:
        $a
}

rule maldoc_find_kernel32_base_method_1 : maldoc {
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 30 00 00 00}
        $a2 = {64 A1 30 00 00 00}
    condition:
        any of them
}

rule maldoc_find_kernel32_base_method_2 : maldoc {
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {31 ?? ?? 30 64 8B ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 1) >= 0xC0) and (((uint8(@a[i] + 1) & 0x38) >> 3) == (uint8(@a[i] + 1) & 0x07)) and ((uint8(@a[i] + 2) & 0xF8) == 0xA0) and (uint8(@a[i] + 6) <= 0x3F) and (((uint8(@a[i] + 6) & 0x38) >> 3) != (uint8(@a[i] + 6) & 0x07)))
}

rule maldoc_find_kernel32_base_method_3 : maldoc {
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {68 30 00 00 00 (58|59|5A|5B|5C|5D|5E|5F) 64 8B ??}
    condition:
        for any i in (1..#a): (((uint8(@a[i] + 5) & 0x07) == (uint8(@a[i] + 8) & 0x07)) and (uint8(@a[i] + 8) <= 0x3F) and (((uint8(@a[i] + 8) & 0x38) >> 3) != (uint8(@a[i] + 8) & 0x07)))
}


rule mwi_document: exploitdoc maldoc {
    meta:
        description = "MWI generated document"
        author = "@Ydklijnsma"
        source = "http://blog.0x3a.com/post/117760824504/analysis-of-a-microsoft-word-intruder-sample"

      strings:
        $field_creation_tag = "{\\field{\\*\\fldinst { INCLUDEPICTURE" nocase
        $mwistat_url = ".php?id=" nocase
        $field_closing_tag = "\\\\* MERGEFORMAT \\\\d}}{\\fldrslt}}" nocase

    condition:
        all of them
}

rule macrocheck : maldoc {
    meta:
        Author      = "Fireeye Labs"
        Date        = "2014/11/30" 
        Description = "Identify office documents with the MACROCHECK credential stealer in them.  It can be run against .doc files or VBA macros extraced from .docx files (vbaProject.bin files)."
        Reference   = "https://www.fireeye.com/blog/threat-research/2014/11/fin4_stealing_insid.html"

    strings:
        $PARAMpword = "pword=" ascii wide
        $PARAMmsg = "msg=" ascii wide
        $PARAMuname = "uname=" ascii
        $userform = "UserForm" ascii wide
        $userloginform = "UserLoginForm" ascii wide
        $invalid = "Invalid username or password" ascii wide
        $up1 = "uploadPOST" ascii wide
        $up2 = "postUpload" ascii wide
 
    condition:
        all of ($PARAM*) or (($invalid or $userloginform or $userform) and ($up1 or $up2))
}


rule Office_AutoOpen_Macro : maldoc {
    meta:
        description = "Detects an Microsoft Office file that contains the AutoOpen Macro function"
        author = "Florian Roth"
        date = "2015-05-28"
        score = 60
        hash1 = "4d00695d5011427efc33c9722c61ced2"
        hash2 = "63f6b20cb39630b13c14823874bd3743"
        hash3 = "66e67c2d84af85a569a04042141164e6"
        hash4 = "a3035716fe9173703941876c2bde9d98"
        hash5 = "7c06cab49b9332962625b16f15708345"
        hash6 = "bfc30332b7b91572bfe712b656ea8a0c"
        hash7 = "25285b8fe2c41bd54079c92c1b761381"
    strings:
        $s1 = "AutoOpen" ascii fullword
        $s2 = "Macros" wide fullword
    condition:
        uint32be(0) == 0xd0cf11e0 and all of ($s*) and filesize < 300000
}

rule Embedded_EXE_Cloaking : maldoc {
    meta:
        description = "Detects an embedded executable in a non-executable file"
        author = "Florian Roth"
        date = "2015/02/27"
        score = 80
    strings:
        $noex_png = { 89 50 4E 47 }
        $noex_pdf = { 25 50 44 46 }
        $noex_rtf = { 7B 5C 72 74 66 31 }
        $noex_jpg = { FF D8 FF E0 }
        $noex_gif = { 47 49 46 38 }
        $mz  = { 4D 5A }
        $a1 = "This program cannot be run in DOS mode" nocase
        $a2 = "This program must be run under Win32"       
    condition:
        (
            ( $noex_png at 0 ) or
            ( $noex_pdf at 0 ) or
            ( $noex_rtf at 0 ) or
            ( $noex_jpg at 0 ) or
            ( $noex_gif at 0 )
        )
        and
        for any i in (1..#mz): ( @a1 < ( @mz[i] + 200 ) or @a2 < ( @mz[i] + 200 ) )
}

rule powershell : maldoc  {
    strings:
        $a = "powershell" nocase
    condition:
    $a
}

rule FE_LEGALSTRIKE_MACRO : maldoc {
       meta:version=".1"
       filetype="MACRO"
       author="Ian.Ahl@fireeye.com @TekDefense"
       date="2017-06-02"
       description="This rule is designed to identify macros with the specific encoding used in the sample 30f149479c02b741e897cdb9ecd22da7."
strings:
       // OBSFUCATION
       $ob1 = "ChrW(114) & ChrW(101) & ChrW(103) & ChrW(115) & ChrW(118) & ChrW(114) & ChrW(51) & ChrW(50) & ChrW(46) & ChrW(101)" ascii wide
       $ob2 = "ChrW(120) & ChrW(101) & ChrW(32) & ChrW(47) & ChrW(115) & ChrW(32) & ChrW(47) & ChrW(110) & ChrW(32) & ChrW(47)" ascii wide
       $ob3 = "ChrW(117) & ChrW(32) & ChrW(47) & ChrW(105) & ChrW(58) & ChrW(104) & ChrW(116) & ChrW(116) & ChrW(112) & ChrW(115)" ascii wide
       $ob4 = "ChrW(58) & ChrW(47) & ChrW(47) & ChrW(108) & ChrW(121) & ChrW(110) & ChrW(99) & ChrW(100) & ChrW(105) & ChrW(115)" ascii wide
       $ob5 = "ChrW(99) & ChrW(111) & ChrW(118) & ChrW(101) & ChrW(114) & ChrW(46) & ChrW(50) & ChrW(98) & ChrW(117) & ChrW(110)" ascii wide
       $ob6 = "ChrW(110) & ChrW(121) & ChrW(46) & ChrW(99) & ChrW(111) & ChrW(109) & ChrW(47) & ChrW(65) & ChrW(117) & ChrW(116)" ascii wide
       $ob7 = "ChrW(111) & ChrW(100) & ChrW(105) & ChrW(115) & ChrW(99) & ChrW(111) & ChrW(118) & ChrW(101) & ChrW(114) & ChrW(32)" ascii wide
       $ob8 = "ChrW(115) & ChrW(99) & ChrW(114) & ChrW(111) & ChrW(98) & ChrW(106) & ChrW(46) & ChrW(100) & ChrW(108) & ChrW(108)" ascii wide
       //$obreg1 = /(\w{5}\s&\s){7}\w{5}/
       //$obreg2 = /(Chrw\(\d{1,3}\)\s&\s){7}/
       // wscript
       $wsobj1 = "Set Obj = CreateObject(\"WScript.Shell\")" ascii wide
       $wsobj2 = "Obj.Run " ascii wide

condition:
        (
              (
                      (uint16(0) != 0x5A4D)
              )
              and
              (
                      all of ($wsobj*) and 3 of ($ob*)
                      or
                      all of ($wsobj*) // and all of ($obreg*)
              )
       )
}

rule Contains_DDE_Protocol: maldoc {
        meta:
                author = "Nick Beede"
                description = "Detect Dynamic Data Exchange protocol in doc/docx"
                reference = "https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/"
                date = "2017-10-19"
                filetype = "Office documents"
        
        strings:
                $doc = {D0 CF 11 E0 A1 B1 1A E1}
                $s1 = { 13 64 64 65 61 75 74 6F 20 } // !!ddeauto
                $s2 = { 13 64 64 65 20 } // !!dde
                $s3 = "dde" nocase
                $s4 = "ddeauto" nocase

        condition:
                ($doc at 0) and 2 of ($s1, $s2, $s3, $s4)
}


rule FE_LEGALSTRIKE_MACRO_2 : maldoc {
       meta:version=".1"
       filetype="MACRO"
       author="Ian.Ahl@fireeye.com @TekDefense"
       date="2017-06-02"
       description="This rule was written to hit on specific variables and powershell command fragments as seen in the macro found in the XLSX file3a1dca21bfe72368f2dd46eb4d9b48c4."
strings:
       // Setting the environment
       $env1 = "Arch = Environ(\"PROCESSOR_ARCHITECTURE\")" ascii wide
       $env2 = "windir = Environ(\"windir\")" ascii wide
       $env3 = "windir + \"\\syswow64\\windowspowershell\\v1.0\\powershell.exe\"" ascii wide
       // powershell command fragments
       $ps1 = "-NoP" ascii wide
       $ps2 = "-NonI" ascii wide
       $ps3 = "-W Hidden" ascii wide
       $ps4 = "-Command" ascii wide
       $ps5 = "New-Object IO.StreamReader" ascii wide
       $ps6 = "IO.Compression.DeflateStream" ascii wide
       $ps7 = "IO.MemoryStream" ascii wide
       $ps8 = ",$([Convert]::FromBase64String" ascii wide
       $ps9 = "ReadToEnd();" ascii wide
       //$psregex1 = /\W\w+\s+\s\".+\"/
condition:
       (
              (
                      (uint16(0) != 0x5A4D)
              )
              and
              (
                      all of ($env*) and 6 of ($ps*)
                      or
                      all of ($env*) and 4 of ($ps*) //and all of ($psregex*)
              )
       )
}
rule FE_LEGALSTRIKE_RTF : maldoc {
    meta:
        version=".1"
        filetype="MACRO"
        author="joshua.kim@FireEye.com"
        date="2017-06-02"
        description="Rtf Phishing Campaign leveraging the CVE 2017-0199 exploit, to point to the domain 2bunnyDOTcom"

    strings:
        $header = "{\\rt" nocase

        $lnkinfo = "4c0069006e006b0049006e0066006f" nocase

        $encoded1 = "4f4c45324c696e6b" nocase
        $encoded2 = "52006f006f007400200045006e007400720079" nocase
        $encoded3 = "4f0062006a0049006e0066006f" nocase
        $encoded4 = "4f006c0065" nocase

        $http1 = "68{" nocase
        $http2 = "74{" nocase
        $http3 = "07{" nocase

        // 2bunny.com
        $domain1 = "32{\\" nocase
        $domain2 = "62{\\" nocase
        $domain3 = "75{\\" nocase
        $domain4 = "6e{\\" nocase
        $domain5 = "79{\\" nocase
        $domain6 = "2e{\\" nocase
        $domain7 = "63{\\" nocase
        $domain8 = "6f{\\" nocase
        $domain9 = "6d{\\" nocase

        $datastore = "\\*\\datastore" nocase

    condition:
        $header at 0 and all of them
}

rule APT_OLE_JSRat : maldoc {
meta:
    author = "Rahul Mohandas"
    Date = "2015-06-16"
    Description = "Targeted attack using Excel/word documents"
strings:
    $header = {D0 CF 11 E0 A1 B1 1A E1}
    $key1 = "AAAAAAAAAA"
    $key2 = "Base64Str" nocase
    $key3 = "DeleteFile" nocase
    $key4 = "Scripting.FileSystemObject" nocase
condition:
    $header at 0 and (all of ($key*) )
}
