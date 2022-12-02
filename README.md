# BinaryAnalysis

Simple Binary Analysis tool for PE-Headers. Going with "Practical Binary Analysis" By Dennis Andriesse.
Currently just reads the Binary and gives back a struct for the PE-Header, PE Optional Header and Section-Headers.

TODO: Read the Section's Bytes out.<br>
TODO: Get Import Address Table Directory (through the DataDirectory).<br>
TODO: Iterate through the DataDirectory and go to the Virtual Addresses of the Entries.<br>
