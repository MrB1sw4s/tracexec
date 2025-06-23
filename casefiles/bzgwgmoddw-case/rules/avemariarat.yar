rule RAT_bzgwgmoddw {
  meta:
    description = "Detects bzgwgmoddw.exe RAT payload dropped by dropper"
    author = "MrB1sw4s"
    sha256 = "A5B365B1AC3044E9094719AF16126AB5C45C381AFAE5A954033E3DE31711D3B9"
    date = "2025-06-23"
  strings:
    $nsis      = "NullsoftInst" ascii
    $werfault  = "WerFault.exe" ascii
    $svchost   = "svchost.exe" ascii
    $mutex     = "bzgwgmoddw" nocase
  condition:
    uint16(0) == 0x5A4D and
    ( $mutex and ($werfault or $nsis) )
}
