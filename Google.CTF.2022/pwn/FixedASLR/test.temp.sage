
import sage

L = companion_matrix(GF(2)['x']("x^64 + x^5 + x^3  + x^2 + 1"), format="bottom")
one = vector(GF(2),64,[0]*63 + [1])

F=GF(2,'z')

R.<k0,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17,k18,k19,k20,k21,k22,k23,k24,k25,k26,k27,k28,k29,k30,k31,k32,k33,k34,k35,k36,k37,k38,k39,k40,k41,k42,k43,k44,k45,k46,k47,k48,k49,k50,k51,k52,k53,k54,k55,k56,k57,k58,k59,k60,k61,k62,k63>=F['k0,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17,k18,k19,k20,k21,k22,k23,k24,k25,k26,k27,k28,k29,k30,k31,k32,k33,k34,k35,k36,k37,k38,k39,k40,k41,k42,k43,k44,k45,k46,k47,k48,k49,k50,k51,k52,k53,k54,k55,k56,k57,k58,k59,k60,k61,k62,k63,k64']
key = vector (R, [k0,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17,k18,k19,k20,k21,k22,k23,k24,k25,k26,k27,k28,k29,k30,k31,k32,k33,k34,k35,k36,k37,k38,k39,k40,k41,k42,k43,k44,k45,k46,k47,k48,k49,k50,k51,k52,k53,k54,k55,k56,k57,k58,k59,k60,k61,k62,k63])

a = L*key + one

clocks = 64 + 64 - 1

for i in range(clocks):
 a = L*a + one


kmat = matrix(R, 64,64)
for i in range(64):
 for j in range(64):
   kmat[i,j] = a[i].coefficient(key[j])

kvec = vector(R, 64)
for i in range(64):
  kvec[i] = a[i].constant_coefficient()

target = 0x19d28388ffd157ce
padlen = 64 -len( list(( ZZ(target).digits(base=2)[::-1] )))
c = vector(GF(2), [0]*padlen + list(( ZZ(target).digits(base=2)[::-1] )))
result = kmat.inverse() * (c-kvec)

print(hex(int(''.join(str(_) for _ in list(result )),2)))
