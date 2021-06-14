rule evil_html: HTML {
    strings:
        $tag = "<html>" fullword nocase
		$s1 = "email" fullword nocase
		$s2 = "password" fullword nocase
		$s3 = "sign on" fullword nocase
		$s4 = "card expire" fullword nocase
		$s5 = "card number" fullword nocase
		$s6 = "cvc" fullword nocase
		$s7 = "account update" fullword nocase
		$s8 = "<script" fullword nocase
    condition:
        $tag and any of ($s*)
}

rule possible_exploit : PDF {
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        version = "0.1"
        weight = 3
        
    strings:
        $magic = { 25 50 44 46 }
        
        $attrib0 = /\/JavaScript /
        $attrib3 = /\/ASCIIHexDecode/
        $attrib4 = /\/ASCII85Decode/

        $action0 = /\/Action/
        $action1 = "Array"
        $shell = "A"
        $cond0 = "unescape"
        $cond1 = "String.fromCharCode"
        
        $nop = "%u9090%u9090"
    condition:
        $magic at 0 and (2 of ($attrib*)) or ($action0 and #shell > 10 and 1 of ($cond*)) or ($action1 and $cond0 and $nop)
}

rule FlashNewfunction: PDF {
   meta:  
      ref = "CVE-2010-1297"
      hide = true
      impact = 5 
      ref = "http://blog.xanda.org/tag/jsunpack/"
   strings:
      $unescape = "unescape" fullword nocase
      $shellcode = /%u[A-Fa-f0-9]{4}/
      $shellcode5 = /(%u[A-Fa-f0-9]{4}){5}/
      $cve20101297 = /\/Subtype ?\/Flash/
   condition:
      ($unescape and $shellcode and $cve20101297) or ($shellcode5 and $cve20101297)
}


rule shellcode_blob_metadata : PDF {
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "When there's a large Base64 blob inserted into metadata fields it often indicates shellcode to later be decoded"
                weight = 4
        strings:
                $magic = { 25 50 44 46 }

                $reg_keyword = /\/Keywords.?\(([a-zA-Z0-9]{200,})/ //~6k was observed in BHEHv2 PDF exploits holding the shellcode
                $reg_author = /\/Author.?\(([a-zA-Z0-9]{200,})/
                $reg_title = /\/Title.?\(([a-zA-Z0-9]{200,})/
                $reg_producer = /\/Producer.?\(([a-zA-Z0-9]{200,})/
                $reg_creator = /\/Creator.?\(([a-zA-Z0-9]{300,})/
                $reg_create = /\/CreationDate.?\(([a-zA-Z0-9]{200,})/

        condition:
                $magic at 0 and 1 of ($reg*)
}


rule suspicious_launch_action : PDF {
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        version = "0.1"
        weight = 2
        
    strings:
        $magic = { 25 50 44 46 }
        
        $attrib0 = /\/Launch/
        $attrib1 = /\/URL /
        $attrib2 = /\/Action/
        $attrib3 = /\/F /

    condition:
        $magic at 0 and 3 of ($attrib*)
}

rule suspicious_embed : PDF {
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        version = "0.1"
        ref = "https://feliam.wordpress.com/2010/01/13/generic-pdf-exploit-hider-embedpdf-py-and-goodbye-av-detection-012010/"
        weight = 2
        
    strings:
        $magic = { 25 50 44 46 }
        
        $meth0 = /\/Launch/
        $meth1 = /\/GoTo(E|R)/ //means go to embedded or remote
        $attrib0 = /\/URL /
        $attrib1 = /\/Action/
        $attrib2 = /\/Filespec/
        
    condition:
        $magic at 0 and 1 of ($meth*) and 2 of ($attrib*)
}

rule suspicious_obfuscation : PDF {
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        version = "0.1"
        weight = 2
        
    strings:
        $magic = { 25 50 44 46 }
        $reg = /\/\w#[a-zA-Z0-9]{2}#[a-zA-Z0-9]{2}/
        
    condition:
        $magic at 0 and #reg > 5
}

rule header_evasion : PDF {
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                description = "3.4.1, 'File Header' of Appendix H states that ' Acrobat viewers require only that the header appear somewhere within the first 1024 bytes of the file.'  Therefore, if you see this trigger then any other rule looking to match the magic at 0 won't be applicable"
                ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
                version = "0.1"
                weight = 3

        strings:
                $magic = { 25 50 44 46 }
        condition:
                $magic in (5..1024) and #magic == 1
}

rule BlackHole_v2 : PDF {
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        version = "0.1"
        ref = "http://fortknoxnetworks.blogspot.no/2012/10/blackhhole-exploit-kit-v-20-url-pattern.html"
        weight = 3
        
    strings:
        $magic = { 25 50 44 46 }
        $content = "Index[5 1 7 1 9 4 23 4 50"
        
    condition:
        $magic at 0 and $content
}


rule XDP_embedded_PDF : PDF {
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        version = "0.1"
        ref = "http://blog.9bplus.com/av-bypass-for-malicious-pdfs-using-xdp"
        weight = 1        

    strings:
        $s1 = "<pdf xmlns="
        $s2 = "<chunk>"
        $s3 = "</pdf>"
        $header0 = "%PDF"
        $header1 = "JVBERi0"

    condition:
        all of ($s*) and 1 of ($header*)
}

rule multiple_filtering : PDF {
meta: 
author = "Glenn Edwards (@hiddenillusion)"
version = "0.2"
weight = 3

    strings:
            $magic = { 25 50 44 46 }
            $attrib = /\/Filter.*(\/ASCIIHexDecode\W+|\/LZWDecode\W+|\/ASCII85Decode\W+|\/FlateDecode\W+|\/RunLengthDecode){2}/ 
            // left out: /CCITTFaxDecode, JBIG2Decode, DCTDecode, JPXDecode, Crypt

    condition: 
            $magic in (0..1024) and $attrib
}

rule executable : executable {
strings:
    $magic1 = { 4d 5a } // MZ
    $magic2 = {46 75 6E 63 74 69 6F 6E} //vbs
    $magic3 = {72 65 67 66} //reg
    $magic4 = {FF 4B 45 59 42 20 20 20} //sys
    $magic5 = {46 57 53} //swf
    $magic6 = {40 65 63 68} //BATCH
condition:
    for any of ($magic*) :($ at 0)
}