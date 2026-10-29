# DFIRArtifactMuseum journal slices

32 KiB from the middle of two `$J` files of
[DFIRArtifactMuseum](https://github.com/AndrewRathbun/DFIRArtifactMuseum) (MIT License,
`Windows/NTFSArtifacts/J/`):

| File | Source | Offset in the source |
| --- | --- | --- |
| `win11_rathbunvm.bin` | `Win11/RathbunVM/$J` | 8,282,112 |
| `win2012r2_stolenszechuan.bin` | `Win2012R2/StolenSzechuan/$J` | 4,608,000 |

`*.dfir_ntfs.tsv` lists every record as [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs)
(Maxim Suhanov, `USN.ChangeJournalParser`, commit ec3ae08) reads it. On the six whole journals
these slices come from, dfir_ntfs and a second, independent parser agree on every V2/V3 record
(1,035,437 records: name, file and parent references, USN and time to 100 ns).
