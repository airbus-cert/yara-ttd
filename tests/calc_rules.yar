rule calc_exe {
  strings:  
    // xored string
    $calc_xor = "calc.exe" xor

    // packed string in little endian
    $calc_le = { 63 6c 61 63 65 78 65 2E }

    // apply `not` to the string and pack in little endian
    $not_calc_le = { 9C 9E 93 9C D1 9A 87 9A }

  condition:
    $calc_xor or $calc_le or $not_calc_le
}
