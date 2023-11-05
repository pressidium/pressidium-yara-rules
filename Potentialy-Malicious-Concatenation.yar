rule SuspiciousVarConcatenation
{
   meta:
      author = "Stefanos Mpatsios"
      date = "01/11/2023"
      description = "This rule created to detect suspicious ascii paths usage and inclution from wp-storage on chrooted env in PHP files."
      reference = "https://github.com/pressidium/pressidium-yara-rules"
   strings:
      //$s6 checks for a pattern like $sdf[12].$erwts[18].$wqewsd[4] even though it is common practice to merge values, usually speaking more than 2 merges is suspicious
      $s6 = /\.\$[A-Za-z0-9]{0,6}\[[0-9]+\]\.\$[A-Za-z0-9]{0,6}\[[0-9]+\]\.\$[A-Za-z0-9]{0,6}\[[0-9]+\]\.\$[A-Za-z0-9]{0,6}\[[0-9]+\]\./
   condition:
      $s6
}

