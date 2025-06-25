
rule detect_PE_1{
    meta:
        author = "Nguyen Dang Manh Cuong"
        description = "This rule will detect PE file using magic number"
        version = "1.0"
        date_created = "2025-05-26"
    strings:
        $magic_number = {4D 5A}
    condition:
        $magic_number at 0
}