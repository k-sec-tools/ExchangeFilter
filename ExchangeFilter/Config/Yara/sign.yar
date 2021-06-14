rule sampleTag: sT {
    strings:
        $tag = "BEGIN:VCARD" fullword nocase
		$s1 = "http.\\" fullword nocase
        $s2 = "https.\\" fullword nocase
    condition:
        $tag and any of ($s*)
}