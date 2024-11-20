import galois

irreducible_polynomials = {
    7: galois.GF(2 ** 7, irreducible_poly = 0x83),          # x^7 + x + 1
    47: galois.GF(2 ** 47, irreducible_poly = 0x800000000021),  # x^47 + x^5 + 1
    61: galois.GF(2 ** 61, irreducible_poly= 0x2000000000000027),  # x^61 + x^5 + x^2 + x + 1
    79: galois.GF(2** 79, irreducible_poly= 0x80000000000000000201)   # x^79 + x^9 + 1
}

print(f'Parámetros: {irreducible_polynomials[7].irreducible_poly}')
print(f'Parámetros: {irreducible_polynomials[47].irreducible_poly}')
print(f'Parámetros: {irreducible_polynomials[61].irreducible_poly}')
print(f'Parámetros: {irreducible_polynomials[79].irreducible_poly}')
