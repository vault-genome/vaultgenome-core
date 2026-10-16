# Veraison's captured GCP SEV-SNP report, in the JSON TSM-report form

`sevsnp-gcp-tsm-report.json` (7980 bytes, sha256
`aa63db181477684671093b59b70cea1b7adb3b4c95b1cf2ecf71905ba020f508`) is
Veraison's test evidence `scheme/sevsnp/test/evidence/sevsnp-gcp-tsm-report.cbor`
(5989 bytes, sha256 `ddc3306caf7fd898cf38b41c81cf528aa21959e8cbceb55e0e3c5593d939605a`;
veraison/services, Apache-2.0; the report PR #488 was tested with) re-encoded
from its CBOR map into ratsd's JSON form with no change to the bytes inside:
`provider` `sev_guest`, `outblob` the 1184-byte report, `auxblob` the host's
4763-byte certificate table (VCEK in DER, ASK, ARK). It is a real GCP n2d
report: REPORT_DATA
`f896ba42…539524` and launch MEASUREMENT
`ccdc5cf01ba25526bd65503d95931b787b4385a3277cfe4448addf9c3e894948ae8cf7b099620e3e22717de2fb5d26fa`.
`rats_live_test.go` posts it to a live Veraison (`VG_VERAISON_URL`) as the
delegated verifier would, with the session nonce = that REPORT_DATA.
