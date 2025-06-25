/*
	This rule uses a regular expression to detect sensitive data
*/
rule sensitive_data
{
	meta:
		author = "Nguyen Dang Manh Cuong."
		description = "Rules is used to detect PII and PHI references."
		version = "1.0"
		date_created = "2025-06-25"
	strings:
	// PII - Pattern 1 = social security number ; Pattern2 = Credit card
	$pii_pattern_1 = /[0-9]{3}-[0-9]{2}-[0-9]{4}/
	$pii_pattern_2 = /[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}/

	// PHI - Pattern 1 = Healthy ID ; Pattern 2 = ICD 9 diagnosis codes ; Pattern 3 = ICD 10 diagnosis codes
        $phi_pattern_1 = /^[A-Za-z0-9]{8,}$/
        $phi_pattern_2 = /\b\d{3}\.\d{0,2}\b/
        $phi_pattern_3 = /\b[A-Z]\d{2}(\.\d{1,4})?\b/

    condition:
        any of ($pii_pattern_1, $pii_pattern_2, $phi_pattern_1, $phi_pattern_2, $phi_pattern_3)
}