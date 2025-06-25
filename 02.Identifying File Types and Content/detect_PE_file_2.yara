
rule detect_PE_2
{
    meta:
        author = "Nguyen Dang Manh Cuong"
        description = "This rule will detect PE file using magic number"
        version = "1.0"
        date_created = "2025-06-25"
    condition:
        uint16(0) == 0x5A4D
}